#!/usr/bin/env node
'use strict';

// A tiny, dependency-free chat server meant to keep working when the
// international internet is cut: no npm packages, no CDNs, no external fonts.
// Run it with `node server.js` on a server inside the country or on any
// machine in a local network.

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const os = require('os');

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
  title: (process.env.CHAT_TITLE || 'گفتگو').slice(0, 80),
  password: process.env.CHAT_PASSWORD || '',
  adminKey: process.env.ADMIN_KEY || '',
  dataDir: path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data')),
  maxHistory: intEnv('MAX_HISTORY', 300),
  maxMessageLength: 2000,
  maxNameLength: 32,
  maxClients: intEnv('MAX_CLIENTS', 1000),
  maxStreamsPerIp: intEnv('MAX_STREAMS_PER_IP', 50),
  trustProxy: process.env.TRUST_PROXY === '1',
  tlsCert: process.env.TLS_CERT || '',
  tlsKey: process.env.TLS_KEY || '',
};

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const PING_INTERVAL_MS = 25 * 1000;
const EVENT_LOG_MAX = 1000;

if (config.password && config.adminKey && config.password === config.adminKey) {
  console.error('CHAT_PASSWORD and ADMIN_KEY must be different.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Storage: messages are kept in memory and saved to a JSON file.
// ---------------------------------------------------------------------------

const DATA_FILE = path.join(config.dataDir, 'messages.json');
const SECRET_FILE = path.join(config.dataDir, 'secret.key');

fs.mkdirSync(config.dataDir, { recursive: true });

let state = { seq: 0, messages: [] };
try {
  const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  if (!raw || !Array.isArray(raw.messages)) throw new Error('unexpected format');
  state = {
    seq: Number(raw.seq) || 0,
    messages: raw.messages.slice(-config.maxHistory),
  };
} catch (err) {
  if (err.code !== 'ENOENT') {
    // Never silently overwrite a file we could not read.
    const backup = DATA_FILE + '.corrupt-' + Date.now();
    try { fs.renameSync(DATA_FILE, backup); } catch (e) { /* ignore */ }
    console.error('Could not read ' + DATA_FILE + ' (' + err.message + '); moved it to ' + backup);
  }
}

let secret = '';
try { secret = fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch (e) { /* first run */ }
if (!secret) {
  secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret + '\n', { mode: 0o600 });
}

let saveTimer = null;
function scheduleSave() {
  if (!saveTimer) saveTimer = setTimeout(saveNow, 1000);
}
function saveNow() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  const tmp = DATA_FILE + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, DATA_FILE);
  } catch (err) {
    console.error('Saving messages failed:', err.message);
  }
}

// Recent events (new/deleted messages) so a client that reconnects after a
// short drop only receives what it missed instead of the whole history.
const eventLog = [];
function logEvent(ev) {
  eventLog.push(ev);
  if (eventLog.length > EVENT_LOG_MAX) eventLog.shift();
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
function makeToken(user) {
  const payload = b64url(JSON.stringify({ u: user.uid, n: user.name, a: user.admin ? 1 : 0, t: Date.now() }));
  return payload + '.' + sign(payload);
}
function verifyToken(token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const dot = token.indexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot);
  if (!safeEqual(token.slice(dot + 1), sign(payload))) return null;
  try {
    const d = JSON.parse(fromB64url(payload).toString('utf8'));
    if (!d || typeof d.t !== 'number' || Date.now() - d.t > TOKEN_TTL_MS) return null;
    return { uid: String(d.u), name: String(d.n), admin: d.a === 1 };
  } catch (e) {
    return null;
  }
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
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
const sendLimiterUser = makeLimiter(5, 5 * 1000);    // per user
const sendLimiterIp = makeLimiter(30, 10 * 1000);    // per IP (mobile carriers share IPs)

// Remembers recent client message ids so a retried send is not duplicated.
const recentCids = new Map();
function rememberCid(key, msg) {
  recentCids.set(key, msg);
  if (recentCids.size > 5000) recentCids.delete(recentCids.keys().next().value);
}

// ---------------------------------------------------------------------------
// Live clients (Server-Sent Events)
// ---------------------------------------------------------------------------

const clients = new Set();

function sseWrite(res, event, data, id) {
  let out = '';
  if (id !== undefined) out += 'id: ' + id + '\n';
  out += 'event: ' + event + '\n';
  out += 'data: ' + JSON.stringify(data) + '\n\n';
  res.write(out);
}
function broadcast(event, data, id) {
  for (const c of clients) sseWrite(c.res, event, data, id);
}

function presenceList() {
  const byUid = new Map();
  for (const c of clients) {
    if (!byUid.has(c.user.uid)) byUid.set(c.user.uid, { uid: c.user.uid, name: c.user.name, admin: c.user.admin });
  }
  return Array.from(byUid.values());
}
let presenceTimer = null;
function schedulePresence() {
  if (presenceTimer) return;
  presenceTimer = setTimeout(() => {
    presenceTimer = null;
    broadcast('presence', presenceList());
  }, 300);
}

setInterval(() => broadcast('ping', Date.now()), PING_INTERVAL_MS).unref();

function addMessage(user, text, cid) {
  state.seq += 1;
  const msg = { id: state.seq, uid: user.uid, name: user.name, admin: user.admin, text: text, ts: Date.now() };
  if (cid) msg.cid = cid;
  state.messages.push(msg);
  if (state.messages.length > config.maxHistory) {
    state.messages.splice(0, state.messages.length - config.maxHistory);
  }
  logEvent({ seq: msg.id, type: 'msg', data: msg });
  scheduleSave();
  broadcast('msg', msg, msg.id);
  return msg;
}

function deleteMessage(id) {
  const idx = state.messages.findIndex((m) => m.id === id);
  if (idx === -1) return false;
  state.messages.splice(idx, 1);
  state.seq += 1;
  const data = { id: id };
  logEvent({ seq: state.seq, type: 'delete', data: data });
  scheduleSave();
  broadcast('delete', data, state.seq);
  return true;
}

function sendInitial(res, since) {
  const firstLogged = eventLog.length ? eventLog[0].seq : state.seq + 1;
  const canReplay = since > 0 && since <= state.seq && since >= firstLogged - 1;
  if (canReplay) {
    for (const ev of eventLog) {
      if (ev.seq > since) sseWrite(res, ev.type, ev.data, ev.seq);
    }
  } else {
    sseWrite(res, 'reset', { messages: state.messages }, state.seq);
  }
}

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

const staticFiles = new Map();
for (const name of fs.readdirSync(PUBLIC_DIR)) {
  const full = path.join(PUBLIC_DIR, name);
  if (!fs.statSync(full).isFile()) continue;
  const ext = path.extname(name).toLowerCase();
  let body = fs.readFileSync(full);
  if (name === 'index.html') {
    body = Buffer.from(body.toString('utf8').replace(/__CHAT_TITLE__/g, escapeHtml(config.title)));
  }
  const compressible = /^(text\/|application\/(javascript|json)|image\/svg)/.test(MIME[ext] || '');
  staticFiles.set('/' + name, {
    body: body,
    gz: compressible ? zlib.gzipSync(body, { level: 9 }) : null,
    type: MIME[ext] || 'application/octet-stream',
    etag: '"' + crypto.createHash('sha1').update(body).digest('hex').slice(0, 16) + '"',
  });
}
staticFiles.set('/', staticFiles.get('/index.html'));

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

function serveStatic(req, res, pathname) {
  const file = staticFiles.get(pathname);
  if (!file) return false;
  const headers = Object.assign({
    'Content-Type': file.type,
    'Cache-Control': 'no-cache',
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

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
  }, SECURITY_HEADERS));
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

async function handleJoin(req, res) {
  if (!joinLimiter(clientIp(req))) return sendJson(res, 429, { error: 'rate_limited' });
  const body = await readJson(req);
  const name = cleanName(body.name);
  if (!name) return sendJson(res, 400, { error: 'bad_name' });

  const pw = typeof body.password === 'string' ? body.password : '';
  let admin = false;
  if (config.adminKey && pw && safeEqual(pw, config.adminKey)) {
    admin = true;
  } else if (config.password ? !safeEqual(pw, config.password) : pw !== '') {
    // With no chat password, a non-empty password can only be an admin attempt.
    return sendJson(res, 403, { error: 'bad_password' });
  }

  // Keep the same identity when re-joining (e.g. after changing the name).
  const prev = verifyToken(body.prevToken);
  const user = { uid: prev ? prev.uid : randomId(12), name: name, admin: admin };
  sendJson(res, 200, { token: makeToken(user), user: user });
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

  if (!sendLimiterUser(user.uid) || !sendLimiterIp(clientIp(req))) {
    return sendJson(res, 429, { error: 'rate_limited' });
  }
  const msg = addMessage(user, text, cid);
  if (cid) rememberCid(cidKey, msg);
  sendJson(res, 200, { message: msg });
}

async function handleDelete(req, res) {
  const user = verifyToken(bearer(req));
  if (!user) return sendJson(res, 401, { error: 'unauthorized' });
  const body = await readJson(req);
  const id = Number(body.id);
  const msg = state.messages.find((m) => m.id === id);
  if (!msg) return sendJson(res, 404, { error: 'not_found' });
  if (!user.admin && msg.uid !== user.uid) return sendJson(res, 403, { error: 'forbidden' });
  deleteMessage(id);
  sendJson(res, 200, { ok: true });
}

function handleStream(req, res, url) {
  const user = verifyToken(url.searchParams.get('token'));
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
  sendInitial(res, since);
  sseWrite(res, 'presence', presenceList());
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
    if (p === '/api/stream') return handleStream(req, res, url);
    if (serveStatic(req, res, p)) return undefined;
    return sendJson(res, 404, { error: 'not_found' });
  }

  if (req.method === 'POST') {
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) {
      return sendJson(res, 415, { error: 'json_required' });
    }
    if (p === '/api/join') return handleJoin(req, res);
    if (p === '/api/send') return handleSend(req, res);
    if (p === '/api/delete') return handleDelete(req, res);
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

const useTls = !!(config.tlsCert && config.tlsKey);
const server = useTls
  ? https.createServer({ cert: fs.readFileSync(config.tlsCert), key: fs.readFileSync(config.tlsKey) }, onRequest)
  : http.createServer(onRequest);

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
  if (!config.password) console.log('Note: CHAT_PASSWORD is not set, so anyone who can reach this address can join.');
  if (!config.adminKey) console.log('Note: ADMIN_KEY is not set, so nobody can delete other people\'s messages.');
  if (!useTls) console.log('Note: running without HTTPS; traffic is not encrypted (see README).');
});

function shutdown() {
  saveNow();
  for (const c of clients) c.res.end();
  server.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
