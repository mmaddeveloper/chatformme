'use strict';

// End-to-end smoke test: starts the real server on a free port with a
// temporary data directory and talks to it over HTTP. Needs Node 18+ (fetch).

const assert = require('assert');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const zlib = require('zlib');
const { spawn } = require('child_process');

const PORT = 30000 + Math.floor(Math.random() * 20000);
const BASE = 'http://127.0.0.1:' + PORT;
const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'chatformme-test-'));
const ENV = Object.assign({}, process.env, {
  PORT: String(PORT),
  HOST: '127.0.0.1',
  DATA_DIR: DATA_DIR,
  CHAT_PASSWORD: 'family-pass',
  ADMIN_KEY: 'admin-secret',
  CHAT_TITLE: 'تست <چت>',
});

let server;

function startServer() {
  return new Promise((resolve, reject) => {
    server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: ENV });
    let out = '';
    server.stdout.on('data', (d) => {
      out += d;
      if (out.includes('is running')) resolve();
    });
    server.stderr.on('data', (d) => process.stderr.write(d));
    server.on('exit', (code) => reject(new Error('server exited early with ' + code)));
  });
}

function stopServer() {
  return new Promise((resolve) => {
    server.removeAllListeners('exit');
    server.on('exit', () => resolve());
    server.kill('SIGTERM');
  });
}

async function call(method, url, body, token) {
  const headers = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(BASE + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, data: await res.json().catch(() => null) };
}

// Minimal SSE reader.
function openStream(token, lastEventId) {
  const events = [];
  const waiters = [];
  // The stream is authenticated by the HttpOnly session cookie, like a browser does.
  const headers = { Cookie: 'cfm_session=' + token };
  if (lastEventId !== undefined) headers['Last-Event-ID'] = String(lastEventId);
  const req = http.get(BASE + '/api/stream', { headers });
  let buffer = '';
  const stream = {
    events,
    status: null,
    close() { req.destroy(); },
    of(type) { return events.filter((e) => e.event === type); },
    next(type, timeoutMs) {
      const idx = events.findIndex((e) => e.event === type && !e.taken);
      if (idx !== -1) { events[idx].taken = true; return Promise.resolve(events[idx]); }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout waiting for ' + type)), timeoutMs || 3000);
        waiters.push({ type, resolve: (ev) => { clearTimeout(timer); resolve(ev); } });
      });
    },
  };
  req.on('response', (res) => {
    stream.status = res.statusCode;
    res.setEncoding('utf8');
    res.on('data', (chunk) => {
      buffer += chunk;
      let i;
      while ((i = buffer.indexOf('\n\n')) !== -1) {
        const block = buffer.slice(0, i);
        buffer = buffer.slice(i + 2);
        const ev = { event: 'message', data: '', id: undefined };
        for (const line of block.split('\n')) {
          if (line.startsWith('event: ')) ev.event = line.slice(7);
          else if (line.startsWith('data: ')) ev.data += line.slice(6);
          else if (line.startsWith('id: ')) ev.id = line.slice(4);
        }
        if (!ev.data) continue;
        ev.data = JSON.parse(ev.data);
        const w = waiters.findIndex((x) => x.type === ev.event);
        if (w !== -1) { ev.taken = true; waiters.splice(w, 1)[0].resolve(ev); }
        events.push(ev);
      }
    });
  });
  req.on('error', () => {});
  return stream;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  await startServer();

  // Static page: title is injected and escaped, gzip works, CSP is set.
  const page = await new Promise((resolve) => {
    http.get(BASE + '/', { headers: { 'Accept-Encoding': 'gzip' } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ res, body: zlib.gunzipSync(Buffer.concat(chunks)).toString('utf8') }));
    });
  });
  assert.strictEqual(page.res.headers['content-encoding'], 'gzip');
  assert.ok(page.res.headers['content-security-policy'].includes("default-src 'self'"));
  assert.ok(page.body.includes('<title>تست &lt;چت&gt;</title>'));
  assert.ok(!/https?:\/\//.test(page.body.replace(/http:\/\/www\.w3\.org\/2000\/svg/g, '')), 'page must not load external resources');

  const cfg = await call('GET', '/api/config');
  assert.deepStrictEqual([cfg.data.passwordRequired, cfg.data.adminEnabled], [true, true]);

  // ---- joining ----
  assert.strictEqual((await call('POST', '/api/join', { name: 'علی', password: 'wrong' })).status, 403);
  assert.strictEqual((await call('POST', '/api/join', { name: '   ', password: 'family-pass' })).data.error, 'bad_name');
  const ali = (await call('POST', '/api/join', { name: '  علی‮  ', password: 'family-pass' })).data;
  assert.strictEqual(ali.user.name, 'علی');
  assert.strictEqual(ali.user.admin, false);
  const sara = (await call('POST', '/api/join', { name: 'سارا', password: 'family-pass' })).data;
  const admin = (await call('POST', '/api/join', { name: 'محمد', password: 'admin-secret' })).data;
  const admin2 = (await call('POST', '/api/join', { name: 'مریم', password: 'admin-secret' })).data;
  assert.strictEqual(admin.user.admin, true);
  assert.strictEqual((await call('GET', '/api/me', undefined, 'bogus.token')).status, 401);

  // ---- session cookie for the live stream ----
  const joinRes = await fetch(BASE + '/api/join', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'کوکی', password: 'family-pass' }),
  });
  const setCookie = joinRes.headers.get('set-cookie');
  assert.ok(/^cfm_session=[^;]+; Path=\/api\/stream; HttpOnly; SameSite=Strict; Max-Age=2592000$/.test(setCookie), setCookie);
  const sessionRes = await fetch(BASE + '/api/session', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + admin.token }, body: '{}',
  });
  assert.ok(/Max-Age=604800/.test(sessionRes.headers.get('set-cookie')), 'admin sessions last 7 days');
  assert.strictEqual((await call('POST', '/api/session', {})).status, 401);
  const logoutRes = await fetch(BASE + '/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.ok(/^cfm_session=; .*Max-Age=0/.test(logoutRes.headers.get('set-cookie')));
  // A token in the URL is no longer accepted (it would end up in access logs).
  const urlToken = await new Promise((resolve) => {
    http.get(BASE + '/api/stream?token=' + encodeURIComponent(admin.token), (r) => { resolve(r.statusCode); r.destroy(); });
  });
  assert.strictEqual(urlToken, 401);
  const headersRes = await fetch(BASE + '/api/config');
  assert.strictEqual(headersRes.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.ok(headersRes.headers.get('permissions-policy').includes('camera=()'));

  // ---- streams ----
  const bad = openStream('nope');
  await sleep(200);
  assert.strictEqual(bad.status, 401);
  bad.close();

  const sAdmin = openStream(admin.token);
  assert.deepStrictEqual((await sAdmin.next('reset')).data.conversations, []);
  const sAli = openStream(ali.token);
  const aliReset = await sAli.next('reset');
  assert.deepStrictEqual(aliReset.data, { messages: [], adminRead: 0 });
  // Visitors only learn how many admins are online, never who the visitors are.
  assert.deepStrictEqual((await sAli.next('presence')).data, { admins: 1 });
  const sSara = openStream(sara.token);
  await sSara.next('reset');
  await sleep(400);
  const adminPresence = sAdmin.of('presence').pop().data;
  assert.deepStrictEqual(adminPresence.visitors.sort(), [ali.user.uid, sara.user.uid].sort());
  assert.strictEqual(adminPresence.admins[0].name, 'محمد');

  // ---- a visitor writes; only admins see it ----
  const sent = await call('POST', '/api/send', { text: 'سلام\r\nکمک لازم دارم ', cid: 'c1', conv: sara.user.uid }, ali.token);
  assert.strictEqual(sent.status, 200);
  assert.strictEqual(sent.data.message.text, 'سلام\nکمک لازم دارم');
  // A visitor cannot write into someone else's conversation.
  assert.strictEqual(sent.data.message.conv, ali.user.uid);
  assert.strictEqual(sent.data.message.from, 'visitor');

  const adminGot = await sAdmin.next('msg');
  assert.strictEqual(adminGot.data.message.id, sent.data.message.id);
  assert.strictEqual(adminGot.data.summary.unread, 1);
  assert.strictEqual(adminGot.data.summary.name, 'علی');
  const aliEcho = await sAli.next('msg');
  assert.deepStrictEqual(Object.keys(aliEcho.data), ['message']);

  // Retrying with the same cid does not create a duplicate.
  const retry = await call('POST', '/api/send', { text: 'سلام\nکمک لازم دارم', cid: 'c1' }, ali.token);
  assert.strictEqual(retry.data.message.id, sent.data.message.id);

  const saraMsg = await call('POST', '/api/send', { text: 'من سارا هستم' }, sara.token);
  await sAdmin.next('msg');
  await sleep(150);
  assert.ok(!sSara.of('msg').some((e) => e.data.message.conv !== sara.user.uid), 'Sara must not see Ali');
  assert.ok(!sAli.of('msg').some((e) => e.data.message.conv !== ali.user.uid), 'Ali must not see Sara');

  assert.strictEqual((await call('POST', '/api/send', { text: '   ' }, ali.token)).data.error, 'empty');
  assert.strictEqual((await call('POST', '/api/send', { text: 'x'.repeat(2001) }, ali.token)).data.error, 'too_long');
  assert.strictEqual((await call('POST', '/api/send', { text: 'hi' })).status, 401);

  // ---- admin inbox and replies ----
  assert.strictEqual((await call('GET', '/api/conversation?conv=' + ali.user.uid, undefined, ali.token)).status, 403);
  const convAli = await call('GET', '/api/conversation?conv=' + ali.user.uid, undefined, admin.token);
  assert.strictEqual(convAli.status, 200);
  assert.deepStrictEqual(convAli.data.messages.map((m) => m.id), [sent.data.message.id]);

  assert.strictEqual((await call('POST', '/api/send', { text: 'hi', conv: 'nobody' }, admin.token)).status, 404);
  // Ids that exist on Object.prototype are not conversations.
  for (const key of ['__proto__', 'constructor', 'toString']) {
    assert.strictEqual((await call('POST', '/api/send', { text: 'hi', conv: key }, admin.token)).status, 404);
    assert.strictEqual((await call('GET', '/api/conversation?conv=' + key, undefined, admin.token)).status, 404);
    assert.strictEqual((await call('POST', '/api/conversation/delete', { conv: key }, admin.token)).status, 404);
  }
  const reply = await call('POST', '/api/send', { text: 'سلام علی، الان کمکت می‌کنیم', conv: ali.user.uid }, admin.token);
  assert.strictEqual(reply.data.message.from, 'admin');
  const aliReply = await sAli.next('msg');
  assert.strictEqual(aliReply.data.message.id, reply.data.message.id);
  await sleep(150);
  assert.ok(!sSara.of('msg').some((e) => e.data.message.id === reply.data.message.id), 'Sara must not see the reply to Ali');
  // Replying marks the conversation as read for admins.
  assert.strictEqual((await sAdmin.next('msg')).data.summary.unread, 0);

  // ---- read receipts ----
  await call('POST', '/api/read', {}, ali.token);
  const visitorRead = await sAdmin.next('read');
  assert.strictEqual(visitorRead.data.visitorRead, reply.data.message.id);
  await call('POST', '/api/read', { conv: sara.user.uid }, admin2.token);
  const saraRead = await sSara.next('read');
  assert.deepStrictEqual(saraRead.data, { adminRead: saraMsg.data.message.id });
  assert.strictEqual((await sAdmin.next('read')).data.summary.unread, 0);

  // ---- rate limit: 5 messages per 5 seconds per visitor (1 already sent) ----
  const statuses = [];
  for (let i = 0; i < 5; i++) statuses.push((await call('POST', '/api/send', { text: 'm' + i }, sara.token)).status);
  assert.deepStrictEqual(statuses, [200, 200, 200, 200, 429]);

  // ---- deleting ----
  assert.strictEqual((await call('POST', '/api/delete', { id: reply.data.message.id }, ali.token)).status, 403);
  assert.strictEqual((await call('POST', '/api/delete', { id: saraMsg.data.message.id }, ali.token)).status, 404);
  assert.strictEqual((await call('POST', '/api/delete', { id: sent.data.message.id }, ali.token)).status, 200);
  assert.deepStrictEqual((await sAli.next('delete')).data, { id: sent.data.message.id });
  const adminDel = await sAdmin.next('delete');
  assert.strictEqual(adminDel.data.conv, ali.user.uid);
  assert.strictEqual((await call('POST', '/api/delete', { id: reply.data.message.id, conv: ali.user.uid }, admin.token)).status, 200);

  // A retried send must not bring back a message that was deleted meanwhile.
  const ghost = await call('POST', '/api/send', { text: 'ghost', cid: 'c-ghost' }, ali.token);
  await call('POST', '/api/delete', { id: ghost.data.message.id }, ali.token);
  const ghostRetry = await call('POST', '/api/send', { text: 'ghost', cid: 'c-ghost' }, ali.token);
  assert.notStrictEqual(ghostRetry.data.message.id, ghost.data.message.id);
  await call('POST', '/api/delete', { id: ghostRetry.data.message.id }, ali.token);

  // Re-joining under a new name updates the admins' inbox right away.
  await call('POST', '/api/join', { name: 'علی رضایی', password: 'family-pass', prevToken: ali.token });
  for (;;) {
    const ev = await sAdmin.next('rename');
    if (ev.data.conv === ali.user.uid) { assert.strictEqual(ev.data.summary.name, 'علی رضایی'); break; }
  }

  // ---- reconnecting only replays what was missed (and only this visitor's) ----
  const lastId = Number(sAli.events.filter((e) => e.id).pop().id);
  sAli.close();
  const missed = await call('POST', '/api/send', { text: 'وقتی نبودی', conv: ali.user.uid }, admin.token);
  await call('POST', '/api/send', { text: 'not for ali', conv: sara.user.uid }, admin.token);
  const sAli2 = openStream(ali.token, lastId);
  const replayed = await sAli2.next('msg');
  assert.strictEqual(replayed.data.message.id, missed.data.message.id);
  await sleep(150);
  assert.ok(!sAli2.of('reset').length, 'should not resend everything');
  assert.strictEqual(sAli2.of('msg').length, 1);

  // ---- deleting a whole conversation ----
  assert.strictEqual((await call('POST', '/api/conversation/delete', { conv: ali.user.uid }, ali.token)).status, 403);
  assert.strictEqual((await call('POST', '/api/conversation/delete', { conv: ali.user.uid }, admin.token)).status, 200);
  await sAli2.next('convdelete');
  assert.strictEqual((await sAdmin.next('convdelete')).data.conv, ali.user.uid);
  sAli2.close();

  // POST without JSON content type is refused (no cross-site form posts).
  const form = await fetch(BASE + '/api/send', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.strictEqual(form.status, 415);

  // ---- wrong passwords lock that IP out for a while ----
  let lastStatus = 0;
  for (let i = 0; i < 12; i++) {
    lastStatus = (await call('POST', '/api/join', { name: 'حدس', password: 'guess-' + i })).status;
    if (lastStatus === 429) break;
  }
  assert.strictEqual(lastStatus, 429);
  const locked = await call('POST', '/api/join', { name: 'مدیر', password: 'admin-secret' });
  assert.strictEqual(locked.data.error, 'too_many_attempts', 'even the right key waits once locked out');

  // ---- data files are private to the server's user ----
  assert.strictEqual(fs.statSync(DATA_DIR).mode & 0o777, 0o700);
  for (const name of ['journal.log', 'secret.key', 'lock']) {
    assert.strictEqual(fs.statSync(path.join(DATA_DIR, name)).mode & 0o777, 0o600, name);
  }

  // ---- persistence across a restart ----
  sAdmin.close();
  sSara.close();
  await stopServer();
  await startServer();
  const sAdmin2 = openStream(admin.token);
  const reset2 = await sAdmin2.next('reset');
  assert.deepStrictEqual(reset2.data.conversations.map((c) => c.uid), [sara.user.uid]);
  const sSara2 = openStream(sara.token);
  const saraReset = await sSara2.next('reset');
  assert.ok(saraReset.data.messages.some((m) => m.text === 'not for ali'));
  assert.ok(saraReset.data.messages.every((m) => m.conv === sara.user.uid));
  // Tokens survive a restart (the signing secret is stored in the data dir).
  assert.strictEqual((await call('GET', '/api/me', undefined, sara.token)).status, 200);
  sAdmin2.close();
  sSara2.close();

  await stopServer();
  console.log('All smoke tests passed.');
}

main().catch(async (err) => {
  console.error(err);
  if (server) server.kill('SIGKILL');
  process.exitCode = 1;
}).finally(() => {
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
});
