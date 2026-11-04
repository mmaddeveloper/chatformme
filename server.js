#!/usr/bin/env node
'use strict';

// A tiny, dependency-free "message us" site meant to keep working when the
// international internet is cut: no npm packages, no CDNs, no external fonts.
//
// Visitors pick a name and get a private conversation with the site's admins.
// Visitors never see each other. Admins (anyone who logs in with ADMIN_KEY)
// share one inbox with every conversation and can reply.
//
// Run it with `node server.js` on a server inside the country or on any
// machine in a local network.

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const os = require('os');
const { Store } = require('./lib/store');

// Everything this server writes (messages, keys) is private to its own user.
process.umask(0o077);

// ---------------------------------------------------------------------------
// Config (all via environment variables)
// ---------------------------------------------------------------------------

function intEnv(name, fallback) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const config = {
  port: intEnv('PORT', 3000),
  host: process.env.HOST || '0.0.0.0',
  title: (process.env.CHAT_TITLE || 'ارتباط با ما').slice(0, 80),
  password: process.env.CHAT_PASSWORD || '',
  adminKey: process.env.ADMIN_KEY || '',
  dataDir: path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data')),
  maxHistory: intEnv('MAX_HISTORY', 300),          // messages kept per conversation
  maxConversations: intEnv('MAX_CONVERSATIONS', 1000),
  maxStorageBytes: intEnv('MAX_STORAGE_MB', 32) * 1024 * 1024, // all conversations together
  maxAccounts: intEnv('MAX_ACCOUNTS', 5000),
  maxConvBytes: 256 * 1024,                        // one conversation
  maxMessageLength: 2000,
  maxNameLength: 32,
  maxClients: intEnv('MAX_CLIENTS', 1000),
  maxStreamsPerIp: intEnv('MAX_STREAMS_PER_IP', 50),
  trustProxy: process.env.TRUST_PROXY === '1',
  tlsCert: process.env.TLS_CERT || '',
  tlsKey: process.env.TLS_KEY || '',
  // Optional plain-HTTP port (usually 80) that only answers certificate
  // validation requests (ACME_WEBROOT) and redirects everything to HTTPS_URL.
  httpPort: intEnv('HTTP_PORT', 0),
  acmeWebroot: process.env.ACME_WEBROOT || '',
  httpsUrl: (process.env.HTTPS_URL || '').replace(/\/+$/, ''),
  // HSTS makes browsers refuse any later certificate warning, which would lock
  // people out if the certificate ever lapses (e.g. during a long shutdown), so
  // it is opt-in.
  hsts: process.env.HSTS === '1',
};

const DAY_MS = 24 * 60 * 60 * 1000;
const VISITOR_TOKEN_TTL_MS = 30 * DAY_MS;
const ADMIN_TOKEN_TTL_MS = 7 * DAY_MS;   // a leaked admin session expires sooner
const ADMIN_KEY_MIN_LENGTH = 12;
const PING_INTERVAL_MS = 25 * 1000;
const EVENT_LOG_MAX = 2000;
const SESSION_COOKIE = 'cfm_session';

if (config.password && config.adminKey && config.password === config.adminKey) {
  console.error('CHAT_PASSWORD and ADMIN_KEY must be different.');
  process.exit(1);
}
if (config.adminKey && Array.from(config.adminKey).length < ADMIN_KEY_MIN_LENGTH) {
  console.error('ADMIN_KEY is too short (at least ' + ADMIN_KEY_MIN_LENGTH + ' characters); a short key can be guessed.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Storage (see lib/store.js): conversations in memory, every change journaled.
// ---------------------------------------------------------------------------

const SECRET_FILE = path.join(config.dataDir, 'secret.key');

let store;
try {
  store = new Store(config.dataDir, {
    maxHistory: config.maxHistory,
    maxConvBytes: config.maxConvBytes,
  }).open();
} catch (err) {
  console.error('Could not open the data directory: ' + err.message);
  process.exit(1);
}

let secret = '';
try { secret = fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch (e) { /* first run */ }
if (!secret) {
  secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret + '\n', { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function randomId(bytes) {
  return b64url(crypto.randomBytes(bytes || 12));
}
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Changing CHAT_PASSWORD or ADMIN_KEY invalidates every issued token.
const tokenKey = crypto.createHash('sha256')
  .update(secret + '\0' + config.password + '\0' + config.adminKey)
  .digest();

function sign(payload) {
  return b64url(crypto.createHmac('sha256', tokenKey).update(payload).digest());
}
// Visitor tokens carry the account's version; changing or resetting the
// password bumps it, which signs out every other device.
function makeToken(user) {
  const data = { u: user.uid, n: user.name, a: user.admin ? 1 : 0, t: Date.now() };
  if (!user.admin) data.v = store.account(user.uid).v;
  const payload = b64url(JSON.stringify(data));
  return payload + '.' + sign(payload);
}
// Checks signature and age only.
function readToken(token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const dot = token.indexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  if (!safeEqual(token.slice(dot + 1), sign(payload))) return null;
  try {
    const d = JSON.parse(fromB64url(payload).toString('utf8'));
    if (!d || typeof d.t !== 'number') return null;
    const ttl = d.a === 1 ? ADMIN_TOKEN_TTL_MS : VISITOR_TOKEN_TTL_MS;
    if (Date.now() - d.t > ttl || d.t > Date.now() + 60 * 1000) return null;
    return d;
  } catch (e) {
    return null;
  }
}
function verifyToken(token) {
  const d = readToken(token);
  if (!d) return null;
  if (d.a === 1) return { uid: String(d.u), name: String(d.n), admin: true };
  // Visitors need an account whose password has not changed since.
  const account = store.account(String(d.u));
  if (!account || account.v !== d.v) return null;
  return { uid: account.uid, name: account.name, admin: false };
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}

function cookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq !== -1 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return '';
}

function isHttps(req) {
  return useTls || (config.trustProxy && /^https$/i.test(String(req.headers['x-forwarded-proto'] || '')));
}

// The live stream authenticates with an HttpOnly cookie rather than a token in
// the URL, so the token never ends up in proxy or server access logs. The
// cookie is only sent to the stream endpoint and never cross-site.
function sessionCookie(req, token, user) {
  const maxAge = token ? Math.floor((user.admin ? ADMIN_TOKEN_TTL_MS : VISITOR_TOKEN_TTL_MS) / 1000) : 0;
  return SESSION_COOKIE + '=' + (token || '') + '; Path=/api/stream; HttpOnly; SameSite=Strict; Max-Age=' + maxAge +
    (isHttps(req) ? '; Secure' : '');
}

// Control characters (keep \n and \t) and, in names, bidi override characters
// that could be used to visually spoof other names. ZWNJ (U+200C), which
// Persian needs, is kept.
const CONTROL_RE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;
const BIDI_RE = /[‪-‮⁦-⁩‎‏؜]/g;

function cleanName(value) {
  if (typeof value !== 'string') return '';
  const name = value.replace(CONTROL_RE, '').replace(BIDI_RE, '').replace(/\s+/g, ' ').trim();
  const len = Array.from(name).length;
  return len >= 1 && len <= config.maxNameLength ? name : '';
}
function cleanText(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/\r\n?/g, '\n').replace(CONTROL_RE, '').replace(/\n{4,}/g, '\n\n\n').trim();
}

function clientIp(req) {
  if (config.trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
    if (req.headers['x-real-ip']) return String(req.headers['x-real-ip']);
  }
  return req.socket.remoteAddress || 'unknown';
}

function makeLimiter(max, windowMs) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [key, arr] of hits) {
      if (!arr.length || now - arr[arr.length - 1] > windowMs) hits.delete(key);
    }
  }, 60 * 1000).unref();
  return function hit(key) {
    const now = Date.now();
    let arr = hits.get(key);
    if (!arr) { arr = []; hits.set(key, arr); }
    while (arr.length && now - arr[0] > windowMs) arr.shift();
    if (arr.length >= max) return false;
    arr.push(now);
    return true;
  };
}

const joinLimiter = makeLimiter(20, 60 * 1000);      // per IP
const sendLimiterUser = makeLimiter(5, 5 * 1000);    // per visitor
const sendLimiterIp = makeLimiter(30, 10 * 1000);    // per IP (mobile carriers share IPs)
// New conversations cost storage; limits are generous because many phones
// share one IP address on mobile networks.
const newConvLimiterIp = makeLimiter(30, 60 * 60 * 1000);
const newConvLimiterAll = makeLimiter(300, 60 * 60 * 1000);
const registerLimiterIp = makeLimiter(10, 60 * 60 * 1000);
const registerLimiterAll = makeLimiter(200, 60 * 60 * 1000);

// Wrong passwords: after 10 from one IP in 15 minutes, that IP must wait.
const LOGIN_FAIL_MAX = 10;
const LOGIN_FAIL_WINDOW_MS = 15 * 60 * 1000;
const loginFailures = new Map(); // ip -> [timestamps]
function recentFailures(ip) {
  const now = Date.now();
  const list = (loginFailures.get(ip) || []).filter((t) => now - t < LOGIN_FAIL_WINDOW_MS);
  if (list.length) loginFailures.set(ip, list); else loginFailures.delete(ip);
  return list;
}
function recordFailure(ip) {
  const list = recentFailures(ip);
  list.push(Date.now());
  loginFailures.set(ip, list);
}
setInterval(() => { for (const ip of Array.from(loginFailures.keys())) recentFailures(ip); }, 60 * 1000).unref();

// Remembers recent client message ids so a retried send is not duplicated.
const recentCids = new Map();
function rememberCid(key, msg) {
  recentCids.set(key, msg);
  if (recentCids.size > 5000) recentCids.delete(recentCids.keys().next().value);
}
function forgetCid(msg) {
  if (msg.cid) recentCids.delete(msg.uid + ':' + msg.cid);
}

function getConv(uid) {
  return store.get(uid);
}

// ---------------------------------------------------------------------------
// Visitor accounts: a unique username and a password (scrypt) per person
// ---------------------------------------------------------------------------

const PASSWORD_MIN = 6;
const PASSWORD_MAX = 128;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const DIACRITICS_RE = /[\u064B-\u065F\u0670\u0640]/g;        // Arabic marks and tatweel
const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

// The same text typed on different keyboards (Arabic or Persian yeh and kaf,
// Persian or Latin digits) should count as the same.
function fold(text) {
  return String(text).normalize('NFKC')
    .replace(INVISIBLE_RE, '')
    .replace(/[\u064A\u0649]/g, '\u06CC')   // ي ى -> ی
    .replace(/\u0643/g, '\u06A9')            // ك -> ک
    .replace(/[\u06F0-\u06F9]/g, (d) => String(d.charCodeAt(0) - 0x06F0))
    .replace(/[\u0660-\u0669]/g, (d) => String(d.charCodeAt(0) - 0x0660));
}

// Usernames that look alike map to the same key, so nobody can register a
// near-copy of someone else's name ("علی" / "علي", "Ali.Reza" / "alireza").
function nameKey(name) {
  return fold(name)
    .replace(DIACRITICS_RE, '')
    .replace(/[\u0622\u0623\u0625\u0671]/g, '\u0627') // آ أ إ ٱ -> ا
    .replace(/\u0629/g, '\u0647')                      // ة -> ه
    .replace(/\u0624/g, '\u0648')                      // ؤ -> و
    .toLowerCase()
    .replace(/[\s._\-]+/g, '');
}

function scryptHash(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(fold(password), Buffer.from(salt, 'base64'), 32, SCRYPT_OPTIONS, (err, key) => {
      if (err) reject(err); else resolve(key.toString('base64'));
    });
  });
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('base64');
  return { salt: salt, hash: await scryptHash(password, salt) };
}
async function checkPassword(account, password) {
  const hash = Buffer.from(await scryptHash(password, account.salt), 'base64');
  const expected = Buffer.from(account.hash, 'base64');
  return hash.length === expected.length && crypto.timingSafeEqual(hash, expected);
}
// Used when the username does not exist, so a miss takes as long as a wrong password.
const DUMMY_ACCOUNT = { salt: crypto.randomBytes(16).toString('base64'), hash: crypto.randomBytes(32).toString('base64') };

function validPassword(password) {
  return typeof password === 'string' && Array.from(password).length >= PASSWORD_MIN && password.length <= PASSWORD_MAX;
}

function readablePassword() {
  const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
  let out = '';
  for (const b of crypto.randomBytes(10)) out += chars[b % chars.length];
  return out;
}

// Wrong passwords for one account: after 10 in 15 minutes the account waits.
const accountFailures = new Map();
function accountLocked(uid) {
  const now = Date.now();
  const list = (accountFailures.get(uid) || []).filter((t) => now - t < LOGIN_FAIL_WINDOW_MS);
  if (list.length) accountFailures.set(uid, list); else accountFailures.delete(uid);
  return list.length >= LOGIN_FAIL_MAX;
}
function recordAccountFailure(uid) {
  accountLocked(uid);
  const list = accountFailures.get(uid) || [];
  list.push(Date.now());
  accountFailures.set(uid, list);
}

// A visitor's open live streams end when their password changes or their
// account is removed, so an old session cannot keep reading.
function disconnectVisitor(uid) {
  for (const c of clients) if (!c.user.admin && c.user.uid === uid) c.res.end();
}

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

function lastActivity(conv) {
  const last = conv.messages[conv.messages.length - 1];
  return last ? last.ts : conv.created;
}

// What the admin inbox shows for one conversation.
function summary(conv) {
  const last = conv.messages[conv.messages.length - 1] || null;
  let unread = 0;
  for (let i = conv.messages.length - 1; i >= 0; i--) {
    const m = conv.messages[i];
    if (m.id <= conv.adminRead) break;
    if (m.from === 'visitor') unread += 1;
  }
  return {
    uid: conv.uid,
    name: conv.name,
    lastTs: lastActivity(conv),
    last: last ? { text: last.text.slice(0, 140), from: last.from } : null,
    account: !!store.account(conv.uid),
    unread: unread,
    adminRead: conv.adminRead,
    visitorRead: conv.visitorRead,
  };
}

function oldestConvExcept(keep) {
  let oldest = null;
  for (const uid of store.uids()) {
    if (uid === keep) continue;
    if (!oldest || lastActivity(store.convs[uid]) < lastActivity(store.convs[oldest])) oldest = uid;
  }
  return oldest;
}

function removeConv(uid, withAccount) {
  const conv = getConv(uid);
  if (!conv && !(withAccount && store.account(uid))) return;
  if (conv) for (const m of conv.messages) forgetCid(m);
  const seq = store.next();
  const op = { op: 'convdel', seq: seq, conv: uid };
  if (withAccount) op.account = true;
  store.commit(op);
  emit({ seq: seq, type: 'convdelete', conv: uid, data: { conv: uid } });
  if (withAccount) disconnectVisitor(uid);
}

// Keep storage bounded: drop the conversations that have been quiet the longest.
function enforceLimits(keep) {
  while (store.uids().length > config.maxConversations || store.totalBytes > config.maxStorageBytes) {
    const oldest = oldestConvExcept(keep);
    if (!oldest) break;
    removeConv(oldest);
  }
}

function addMessage(uid, user, text, cid) {
  const msg = {
    id: store.next(), conv: uid, from: user.admin ? 'admin' : 'visitor',
    uid: user.uid, name: user.name, text: text, ts: Date.now(),
  };
  if (cid) msg.cid = cid;
  store.commit({ op: 'msg', seq: msg.id, m: msg });
  const conv = getConv(uid);
  emit({ seq: msg.id, type: 'msg', conv: uid, data: { message: msg, summary: summary(conv) } });
  enforceLimits(uid);
  return msg;
}

// ---------------------------------------------------------------------------
// Live clients (Server-Sent Events)
// ---------------------------------------------------------------------------

const clients = new Set();

// Recent events so a client that reconnects after a short drop only receives
// what it missed instead of everything.
const eventLog = [];

function sseWrite(res, event, data, id) {
  let out = '';
  if (id !== undefined) out += 'id: ' + id + '\n';
  out += 'event: ' + event + '\n';
  out += 'data: ' + JSON.stringify(data) + '\n\n';
  res.write(out);
}

// Admins see every event in full. A visitor only sees events about their own
// conversation, and only the parts meant for them.
function payloadFor(client, ev) {
  if (client.user.admin) return ev.data;
  if (ev.conv !== client.user.uid) return null;
  if (ev.type === 'msg') return { message: ev.data.message };
  if (ev.type === 'delete') return { id: ev.data.id };
  if (ev.type === 'read') return { adminRead: ev.data.adminRead };
  if (ev.type === 'convdelete') return {};
  return null;
}

function emit(ev) {
  eventLog.push(ev);
  if (eventLog.length > EVENT_LOG_MAX) eventLog.shift();
  for (const c of clients) {
    const data = payloadFor(c, ev);
    if (data) sseWrite(c.res, ev.type, data, ev.seq);
  }
}

function resetPayload(client) {
  if (client.user.admin) {
    const list = store.uids().map((uid) => summary(store.convs[uid]));
    list.sort((a, b) => b.lastTs - a.lastTs);
    return { conversations: list };
  }
  const conv = getConv(client.user.uid);
  return { messages: conv ? conv.messages : [], adminRead: conv ? conv.adminRead : 0 };
}

function sendInitial(client, since) {
  const firstLogged = eventLog.length ? eventLog[0].seq : store.seq + 1;
  const canReplay = since > 0 && since <= store.seq && since >= firstLogged - 1;
  if (canReplay) {
    for (const ev of eventLog) {
      if (ev.seq <= since) continue;
      const data = payloadFor(client, ev);
      if (data) sseWrite(client.res, ev.type, data, ev.seq);
    }
    sseWrite(client.res, 'ping', Date.now(), store.seq);
  } else {
    sseWrite(client.res, 'reset', resetPayload(client), store.seq);
  }
}

// Who is online. Admins learn which visitors are online; visitors only learn
// how many admins are online.
function presence() {
  const admins = new Map();
  const visitors = new Set();
  for (const c of clients) {
    if (c.user.admin) admins.set(c.user.uid, c.user.name);
    else visitors.add(c.user.uid);
  }
  return {
    admins: Array.from(admins, (entry) => ({ uid: entry[0], name: entry[1] })),
    visitors: Array.from(visitors),
  };
}
function presenceFor(client, p) {
  return client.user.admin ? p : { admins: p.admins.length };
}

let presenceTimer = null;
let lastAdminCount = -1;
function schedulePresence() {
  if (presenceTimer) return;
  presenceTimer = setTimeout(() => {
    presenceTimer = null;
    const p = presence();
    const adminCountChanged = p.admins.length !== lastAdminCount;
    lastAdminCount = p.admins.length;
    for (const c of clients) {
      if (c.user.admin || adminCountChanged) sseWrite(c.res, 'presence', presenceFor(c, p));
    }
  }, 300);
}

// The ping carries the current sequence number so every client's position
// moves forward even when the events in between were not meant for it.
setInterval(() => {
  for (const c of clients) sseWrite(c.res, 'ping', Date.now(), store.seq);
}, PING_INTERVAL_MS).unref();

// ---------------------------------------------------------------------------
// Static files (served from memory, gzip-compressed once at startup)
// ---------------------------------------------------------------------------

const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Optional bundled font: drop Vazirmatn .woff2 files into public/fonts/ and the
// matching @font-face rules are added to style.css automatically.
const FONT_WEIGHTS = {
  Thin: '100', ExtraLight: '200', Light: '300', Regular: '400', Medium: '500',
  SemiBold: '600', Bold: '700', ExtraBold: '800', Black: '900', Variable: '100 900',
};
function fontFaceCss() {
  let names = [];
  try { names = fs.readdirSync(path.join(PUBLIC_DIR, 'fonts')); } catch (e) { return ''; }
  let css = '';
  for (const name of names.sort()) {
    const m = /^Vazirmatn(?:-(\w+)|\[wght\])\.woff2$/.exec(name);
    if (!m) continue;
    const weight = m[1] ? FONT_WEIGHTS[m[1]] : FONT_WEIGHTS.Variable;
    if (!weight) continue;
    css += '@font-face{font-family:"Vazirmatn";src:url("/fonts/' + encodeURIComponent(name) +
      '") format("woff2");font-weight:' + weight + ';font-style:normal;font-display:swap}\n';
  }
  return css;
}

const staticFiles = new Map();

function loadStaticDir(dir, prefix) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      if (!prefix && name === 'fonts') loadStaticDir(full, '/fonts');
      continue;
    }
    if (!stat.isFile() || name.startsWith('.')) continue;
    const ext = path.extname(name).toLowerCase();
    let body = fs.readFileSync(full);
    if (!prefix && name === 'index.html') {
      body = Buffer.from(body.toString('utf8').replace(/__CHAT_TITLE__/g, escapeHtml(config.title)));
    }
    if (!prefix && name === 'style.css') {
      body = Buffer.concat([Buffer.from(fontFaceCss()), body]);
    }
    const compressible = /^(text\/|application\/(javascript|json)|image\/svg)/.test(MIME[ext] || '');
    staticFiles.set((prefix || '') + '/' + name, {
      body: body,
      gz: compressible ? zlib.gzipSync(body, { level: 9 }) : null,
      type: MIME[ext] || 'application/octet-stream',
      etag: '"' + crypto.createHash('sha1').update(body).digest('hex').slice(0, 16) + '"',
      cache: prefix === '/fonts' ? 'public, max-age=2592000' : 'no-cache',
    });
  }
}

loadStaticDir(PUBLIC_DIR, '');
staticFiles.set('/', staticFiles.get('/index.html'));

const useTls = !!(config.tlsCert && config.tlsKey);

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};
if (useTls && config.hsts) SECURITY_HEADERS['Strict-Transport-Security'] = 'max-age=15552000';

function serveStatic(req, res, pathname) {
  let key = pathname;
  try { key = decodeURIComponent(pathname); } catch (e) { /* keep as is */ }
  const file = staticFiles.get(key);
  if (!file) return false;
  const headers = Object.assign({
    'Content-Type': file.type,
    'Cache-Control': file.cache,
    ETag: file.etag,
    Vary: 'Accept-Encoding',
  }, SECURITY_HEADERS);
  if (req.headers['if-none-match'] === file.etag) {
    res.writeHead(304, headers);
    res.end();
    return true;
  }
  let body = file.body;
  if (file.gz && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
    body = file.gz;
    headers['Content-Encoding'] = 'gzip';
  }
  headers['Content-Length'] = body.length;
  res.writeHead(200, headers);
  res.end(req.method === 'HEAD' ? undefined : body);
  return true;
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

function sendJson(res, status, data, extraHeaders) {
  const body = JSON.stringify(data);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
  }, SECURITY_HEADERS, extraHeaders || {}));
  res.end(body);
}

function httpError(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

function readJson(req, limit) {
  limit = limit || 16 * 1024;
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(httpError(413, 'too_large'));
        req.destroy();
      } else {
        chunks.push(chunk);
      }
    });
    req.on('end', () => {
      try {
        const data = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        resolve(data && typeof data === 'object' ? data : {});
      } catch (e) {
        reject(httpError(400, 'bad_json'));
      }
    });
    req.on('error', reject);
  });
}

function loginLocked(ip) {
  return recentFailures(ip).length >= LOGIN_FAIL_MAX;
}
function wrongPassword(res, ip, code, what) {
  recordFailure(ip);
  console.warn('Wrong ' + what + ' from ' + ip + ' (' + recentFailures(ip).length + ' in the last 15 minutes)');
  return sendJson(res, 403, { error: code });
}
function signedIn(req, res, user) {
  const token = makeToken(user);
  return sendJson(res, 200, { token: token, user: user }, { 'Set-Cookie': sessionCookie(req, token, user) });
}

async function handleRegister(req, res) {
  const ip = clientIp(req);
  if (loginLocked(ip)) return sendJson(res, 429, { error: 'too_many_attempts' });
  if (!joinLimiter(ip)) return sendJson(res, 429, { error: 'rate_limited' });
  const body = await readJson(req);
  const name = cleanName(body.username);
  const key = name ? nameKey(name) : '';
  if (!name || Array.from(key).length < 2) return sendJson(res, 400, { error: 'bad_name' });
  if (!validPassword(body.password)) return sendJson(res, 400, { error: 'weak_password' });
  if (config.password && !safeEqual(String(body.sitePassword || ''), config.password)) {
    return wrongPassword(res, ip, 'bad_site_password', 'site password');
  }
  if (store.accountByKey(key)) return sendJson(res, 409, { error: 'name_taken' });
  if (store.accountCount() >= config.maxAccounts) return sendJson(res, 503, { error: 'full' });
  if (!registerLimiterIp(ip) || !registerLimiterAll('all')) return sendJson(res, 429, { error: 'rate_limited' });

  // A conversation started on this device before accounts existed is kept.
  const prev = readToken(body.prevToken);
  const claim = prev && prev.a !== 1 && typeof prev.u === 'string' && !store.account(prev.u) ? prev.u : null;
  const uid = claim || randomId(12);
  const pw = await hashPassword(body.password);
  if (store.accountByKey(key) || store.account(uid)) return sendJson(res, 409, { error: 'name_taken' });
  const seq = store.next();
  store.commit({ op: 'account', seq: seq, uid: uid, name: name, key: key, salt: pw.salt, hash: pw.hash, created: Date.now() });
  const conv = getConv(uid);
  if (conv) emit({ seq: seq, type: 'rename', conv: uid, data: { conv: uid, summary: summary(conv) } });
  return signedIn(req, res, { uid: uid, name: name, admin: false });
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  if (loginLocked(ip)) return sendJson(res, 429, { error: 'too_many_attempts' });
  if (!joinLimiter(ip)) return sendJson(res, 429, { error: 'rate_limited' });
  const body = await readJson(req);
  const name = cleanName(body.username);
  const account = name ? store.accountByKey(nameKey(name)) : null;
  if (account && accountLocked(account.uid)) return sendJson(res, 429, { error: 'account_locked' });
  const password = typeof body.password === 'string' ? body.password.slice(0, PASSWORD_MAX) : '';
  const ok = await checkPassword(account || DUMMY_ACCOUNT, password);
  if (!account || !ok) {
    if (account) recordAccountFailure(account.uid);
    return wrongPassword(res, ip, 'bad_credentials', 'password for "' + (name || '') + '"');
  }
  accountFailures.delete(account.uid);
  return signedIn(req, res, { uid: account.uid, name: account.name, admin: false });
}

async function handleAdminLogin(req, res) {
  const ip = clientIp(req);
  if (loginLocked(ip)) return sendJson(res, 429, { error: 'too_many_attempts' });
  if (!joinLimiter(ip)) return sendJson(res, 429, { error: 'rate_limited' });
  const body = await readJson(req);
  const name = cleanName(body.name);
  if (!name) return sendJson(res, 400, { error: 'bad_name' });
  if (!config.adminKey || !safeEqual(String(body.key || ''), config.adminKey)) {
    return wrongPassword(res, ip, 'bad_password', 'admin key');
  }
  // The same name gets the same id on every login, so earlier replies still count as "mine".
  const uid = 'a_' + b64url(crypto.createHash('sha256').update('admin:' + nameKey(name)).digest()).slice(0, 16);
  return signedIn(req, res, { uid: uid, name: name, admin: true });
}

async function handleChangePassword(req, res) {
  const ip = clientIp(req);
  const user = verifyToken(bearer(req));
  if (!user || user.admin) return sendJson(res, 401, { error: 'unauthorized' });
  if (loginLocked(ip) || accountLocked(user.uid)) return sendJson(res, 429, { error: 'too_many_attempts' });
  const body = await readJson(req);
  if (!validPassword(body.next)) return sendJson(res, 400, { error: 'weak_password' });
  const account = store.account(user.uid);
  if (!(await checkPassword(account, String(body.current || '').slice(0, PASSWORD_MAX)))) {
    recordAccountFailure(user.uid);
    return wrongPassword(res, ip, 'bad_credentials', 'current password for "' + account.name + '"');
  }
  const pw = await hashPassword(body.next);
  store.commit({ op: 'passwd', seq: store.next(), uid: user.uid, salt: pw.salt, hash: pw.hash, v: account.v + 1 });
  disconnectVisitor(user.uid); // other devices are signed out; this one gets a new token below
  return signedIn(req, res, user);
}

// For a visitor who forgot their password: the admin gets a new one to pass on.
async function handleResetPassword(req, res) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  if (!user.admin) return sendJson(res, 403, { error: 'forbidden' });
  const body = await readJson(req);
  const account = store.account(String(body.conv));
  if (!account) return sendJson(res, 404, { error: 'not_found' });
  const password = readablePassword();
  const pw = await hashPassword(password);
  store.commit({ op: 'passwd', seq: store.next(), uid: account.uid, salt: pw.salt, hash: pw.hash, v: account.v + 1 });
  accountFailures.delete(account.uid);
  disconnectVisitor(account.uid);
  return sendJson(res, 200, { username: account.name, password: password });
}

// Sets the stream cookie for a page that already holds a token (after a reload).
function handleSession(req, res) {
  const token = bearer(req);
  const user = verifyToken(token);
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, token, user) });
}

function handleLogout(req, res) {
  return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', { admin: false }) });
}

async function handleSend(req, res) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  const body = await readJson(req, 32 * 1024);
  const text = cleanText(body.text);
  if (!text) return sendJson(res, 400, { error: 'empty' });
  if (text.length > config.maxMessageLength) return sendJson(res, 400, { error: 'too_long' });

  const cid = typeof body.cid === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(body.cid) ? body.cid : '';
  const cidKey = user.uid + ':' + cid;
  if (cid && recentCids.has(cidKey)) return sendJson(res, 200, { message: recentCids.get(cidKey) });

  // Admins reply to an existing conversation; visitors always write to their own.
  let conv = null;
  if (user.admin) {
    conv = getConv(String(body.conv));
    if (!conv) return sendJson(res, 404, { error: 'not_found' });
  }
  const ip = clientIp(req);
  if ((!user.admin && !sendLimiterUser(user.uid)) || !sendLimiterIp(ip)) {
    return sendJson(res, 429, { error: 'rate_limited' });
  }
  if (!conv) {
    conv = getConv(user.uid);
    if (!conv && (!newConvLimiterIp(ip) || !newConvLimiterAll('all'))) {
      return sendJson(res, 429, { error: 'rate_limited' });
    }
  }

  const msg = addMessage(conv ? conv.uid : user.uid, user, text, cid);
  if (cid) rememberCid(cidKey, msg);
  sendJson(res, 200, { message: msg });
}

async function handleDelete(req, res) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  const body = await readJson(req);
  const conv = getConv(user.admin ? String(body.conv) : user.uid);
  const id = Number(body.id);
  const idx = conv ? conv.messages.findIndex((m) => m.id === id) : -1;
  if (idx === -1) return sendJson(res, 404, { error: 'not_found' });
  // Visitors may delete their own messages; admins may delete any message.
  if (!user.admin && conv.messages[idx].from !== 'visitor') return sendJson(res, 403, { error: 'forbidden' });

  forgetCid(conv.messages[idx]);
  const seq = store.next();
  store.commit({ op: 'del', seq: seq, conv: conv.uid, id: id });
  emit({ seq: seq, type: 'delete', conv: conv.uid, data: { id: id, conv: conv.uid, summary: summary(conv) } });
  sendJson(res, 200, { ok: true });
}

async function handleRead(req, res) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  const body = await readJson(req);
  const conv = getConv(user.admin ? String(body.conv) : user.uid);
  if (!conv) return sendJson(res, 200, { ok: true });
  const last = conv.messages.length ? conv.messages[conv.messages.length - 1].id : 0;
  const field = user.admin ? 'adminRead' : 'visitorRead';
  if (last > conv[field]) {
    const seq = store.next();
    const op = { op: 'read', seq: seq, conv: conv.uid };
    op[field] = last;
    store.commit(op);
    emit({
      seq: seq, type: 'read', conv: conv.uid,
      data: { conv: conv.uid, adminRead: conv.adminRead, visitorRead: conv.visitorRead, summary: summary(conv) },
    });
  }
  sendJson(res, 200, { ok: true });
}

async function handleDeleteConversation(req, res) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  if (!user.admin) return sendJson(res, 403, { error: 'forbidden' });
  const body = await readJson(req);
  const uid = String(body.conv);
  if (!getConv(uid) && !store.account(uid)) return sendJson(res, 404, { error: 'not_found' });
  removeConv(uid, true);
  sendJson(res, 200, { ok: true });
}

function handleGetConversation(req, res, url) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  if (!user.admin) return sendJson(res, 403, { error: 'forbidden' });
  const conv = getConv(String(url.searchParams.get('conv')));
  if (!conv) return sendJson(res, 404, { error: 'not_found' });
  return sendJson(res, 200, { summary: summary(conv), messages: conv.messages });
}

function handleStream(req, res, url) {
  const user = verifyToken(cookie(req, SESSION_COOKIE));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });

  const ip = clientIp(req);
  let fromIp = 0;
  for (const c of clients) if (c.ip === ip) fromIp += 1;
  if (clients.size >= config.maxClients || fromIp >= config.maxStreamsPerIp) {
    return sendJson(res, 503, { error: 'too_many_connections' });
  }

  res.writeHead(200, Object.assign({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no', // tell nginx not to buffer the stream
  }, SECURITY_HEADERS));
  req.socket.setNoDelay(true);
  req.socket.setKeepAlive(true, PING_INTERVAL_MS);
  res.write('retry: 3000\n\n');

  const client = { res: res, user: user, ip: ip };
  clients.add(client);

  // EventSource sends Last-Event-ID when it reconnects by itself; otherwise
  // the page passes the last id it saw in `since`.
  const header = req.headers['last-event-id'];
  const since = parseInt(header !== undefined ? header : url.searchParams.get('since'), 10) || 0;
  sendInitial(client, since);
  sseWrite(res, 'presence', presenceFor(client, presence()));
  schedulePresence();

  const cleanup = () => {
    if (clients.delete(client)) schedulePresence();
  };
  req.on('close', cleanup);
  res.on('error', cleanup);
}

async function handle(req, res) {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch (e) {
    return sendJson(res, 400, { error: 'bad_url' });
  }
  const p = url.pathname;

  if (req.method === 'GET' || req.method === 'HEAD') {
    if (p === '/api/config') {
      return sendJson(res, 200, {
        title: config.title,
        passwordRequired: !!config.password,
        adminEnabled: !!config.adminKey,
        maxMessageLength: config.maxMessageLength,
        maxNameLength: config.maxNameLength,
      });
    }
    if (p === '/api/me') {
      const user = verifyToken(bearer(req));
      return user ? sendJson(res, 200, { user: user }) : sendJson(res, 401, { error: 'unauthorized' });
    }
    if (p === '/api/conversation') return handleGetConversation(req, res, url);
    if (p === '/api/stream') return handleStream(req, res, url);
    if (serveStatic(req, res, p)) return undefined;
    return sendJson(res, 404, { error: 'not_found' });
  }

  if (req.method === 'POST') {
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) {
      return sendJson(res, 415, { error: 'json_required' });
    }
    if (p === '/api/register') return handleRegister(req, res);
    if (p === '/api/login') return handleLogin(req, res);
    if (p === '/api/admin/login') return handleAdminLogin(req, res);
    if (p === '/api/account/password') return handleChangePassword(req, res);
    if (p === '/api/admin/reset-password') return handleResetPassword(req, res);
    if (p === '/api/session') return handleSession(req, res);
    if (p === '/api/logout') return handleLogout(req, res);
    if (p === '/api/send') return handleSend(req, res);
    if (p === '/api/delete') return handleDelete(req, res);
    if (p === '/api/read') return handleRead(req, res);
    if (p === '/api/conversation/delete') return handleDeleteConversation(req, res);
    return sendJson(res, 404, { error: 'not_found' });
  }

  return sendJson(res, 405, { error: 'method_not_allowed' });
}

function onRequest(req, res) {
  handle(req, res).catch((err) => {
    if (!err.status) console.error(err);
    if (!res.headersSent) sendJson(res, err.status || 500, { error: err.code || 'server_error' });
    else res.end();
  });
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

function tlsOptions() {
  return { cert: fs.readFileSync(config.tlsCert), key: fs.readFileSync(config.tlsKey), minVersion: 'TLSv1.2' };
}

const server = useTls ? https.createServer(tlsOptions(), onRequest) : http.createServer(onRequest);

// A renewed certificate is picked up on SIGHUP (systemctl reload) without
// dropping anyone's connection.
process.on('SIGHUP', () => {
  if (!useTls) return;
  try {
    server.setSecureContext(tlsOptions());
    console.log('Reloaded the TLS certificate.');
  } catch (err) {
    console.error('Could not reload the TLS certificate: ' + err.message);
  }
});

// ---------------------------------------------------------------------------
// Optional plain-HTTP helper port: certificate validation and redirect to HTTPS
// ---------------------------------------------------------------------------

const ACME_PREFIX = '/.well-known/acme-challenge/';

function onHttpHelper(req, res) {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch (e) { url = new URL('http://localhost/'); }
  if (url.pathname.startsWith(ACME_PREFIX) && config.acmeWebroot) {
    const token = url.pathname.slice(ACME_PREFIX.length);
    if (/^[A-Za-z0-9_-]{1,256}$/.test(token)) {
      try {
        const body = fs.readFileSync(path.join(config.acmeWebroot, ACME_PREFIX, token));
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
        return res.end(body);
      } catch (e) { /* fall through to 404 */ }
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('not found');
  }
  if (config.httpsUrl) {
    res.writeHead(301, { Location: config.httpsUrl + url.pathname + url.search, 'Content-Type': 'text/plain' });
    return res.end('moved to ' + config.httpsUrl);
  }
  res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
  return res.end('HTTPS is being set up; try again in a minute.');
}

if (config.httpPort) {
  const helper = http.createServer(onHttpHelper);
  helper.headersTimeout = 10 * 1000;
  helper.requestTimeout = 10 * 1000;
  helper.on('error', (err) => {
    console.error('Could not listen on HTTP port ' + config.httpPort + ': ' + err.message);
    process.exit(1);
  });
  helper.listen(config.httpPort, config.host);
}

// Slow or half-open clients must not tie up the server (live streams are
// unaffected: their request is complete as soon as the headers arrive).
server.headersTimeout = 15 * 1000;
server.requestTimeout = 30 * 1000;
server.maxConnections = config.maxClients * 2;

server.listen(config.port, config.host, () => {
  const proto = useTls ? 'https' : 'http';
  console.log('chatformme is running. Open one of these addresses:');
  if (config.host === '0.0.0.0' || config.host === '::') {
    console.log('  ' + proto + '://localhost:' + config.port);
    const nets = os.networkInterfaces();
    for (const name of Object.keys(nets)) {
      for (const addr of nets[name] || []) {
        if ((addr.family === 'IPv4' || addr.family === 4) && !addr.internal) {
          console.log('  ' + proto + '://' + addr.address + ':' + config.port);
        }
      }
    }
  } else {
    console.log('  ' + proto + '://' + config.host + ':' + config.port);
  }
  if (!config.adminKey) console.log('WARNING: ADMIN_KEY is not set, so nobody can read or answer messages. Set ADMIN_KEY.');
  if (!config.password) console.log('Note: CHAT_PASSWORD is not set, so anyone who can reach this address can send you messages.');
  if (!useTls) console.log('Note: running without HTTPS; traffic is not encrypted (see README).');
});

function shutdown() {
  for (const c of clients) c.res.end();
  server.close();
  store.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
