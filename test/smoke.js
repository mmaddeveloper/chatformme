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
function openStream(token, since, lastEventId) {
  const events = [];
  const waiters = [];
  const headers = {};
  if (lastEventId !== undefined) headers['Last-Event-ID'] = String(lastEventId);
  const req = http.get(BASE + '/api/stream?token=' + encodeURIComponent(token) + '&since=' + (since || 0), { headers });
  let buffer = '';
  const stream = {
    events,
    status: null,
    close() { req.destroy(); },
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
  assert.ok(!/https?:\/\//.test(page.body.replace('http://www.w3.org/2000/svg', '')), 'page must not load external resources');

  const cfg = await call('GET', '/api/config');
  assert.deepStrictEqual(
    [cfg.data.passwordRequired, cfg.data.adminEnabled],
    [true, true]
  );

  // Joining.
  assert.strictEqual((await call('POST', '/api/join', { name: 'علی', password: 'wrong' })).status, 403);
  assert.strictEqual((await call('POST', '/api/join', { name: '   ', password: 'family-pass' })).data.error, 'bad_name');
  const ali = (await call('POST', '/api/join', { name: '  علی‮  ', password: 'family-pass' })).data;
  assert.strictEqual(ali.user.name, 'علی');
  assert.strictEqual(ali.user.admin, false);
  const sara = (await call('POST', '/api/join', { name: 'سارا', password: 'family-pass' })).data;
  const admin = (await call('POST', '/api/join', { name: 'مدیر', password: 'admin-secret' })).data;
  assert.strictEqual(admin.user.admin, true);

  // Re-joining with the previous token keeps the identity.
  const ali2 = (await call('POST', '/api/join', { name: 'علی رضا', password: 'family-pass', prevToken: ali.token })).data;
  assert.strictEqual(ali2.user.uid, ali.user.uid);

  assert.strictEqual((await call('GET', '/api/me', undefined, 'bogus.token')).status, 401);
  assert.strictEqual((await call('GET', '/api/me', undefined, ali.token)).data.user.name, 'علی');

  // Streams.
  const bad = openStream('nope');
  await sleep(200);
  assert.strictEqual(bad.status, 401);
  bad.close();

  const s1 = openStream(sara.token);
  const reset = await s1.next('reset');
  assert.deepStrictEqual(reset.data.messages, []);
  const presence = await s1.next('presence');
  assert.ok(presence.data.some((u) => u.name === 'سارا'));

  // Sending.
  const sent = await call('POST', '/api/send', { text: 'سلام\r\nخوبی؟ ', cid: 'c1' }, ali.token);
  assert.strictEqual(sent.status, 200);
  assert.strictEqual(sent.data.message.text, 'سلام\nخوبی؟');
  const got = await s1.next('msg');
  assert.strictEqual(got.data.id, sent.data.message.id);
  assert.strictEqual(got.id, String(sent.data.message.id));

  // Retrying with the same cid does not create a duplicate.
  const retry = await call('POST', '/api/send', { text: 'سلام\nخوبی؟', cid: 'c1' }, ali.token);
  assert.strictEqual(retry.data.message.id, sent.data.message.id);
  await sleep(150);
  assert.strictEqual(s1.events.filter((e) => e.event === 'msg').length, 1);

  assert.strictEqual((await call('POST', '/api/send', { text: '   ' }, ali.token)).data.error, 'empty');
  assert.strictEqual((await call('POST', '/api/send', { text: 'x'.repeat(2001) }, ali.token)).data.error, 'too_long');
  assert.strictEqual((await call('POST', '/api/send', { text: 'hi' })).status, 401);

  // Rate limit: 5 messages per 5 seconds per user (1 already sent).
  const statuses = [];
  for (let i = 0; i < 5; i++) statuses.push((await call('POST', '/api/send', { text: 'm' + i }, sara.token)).status);
  assert.deepStrictEqual(statuses, [200, 200, 200, 200, 200]);
  assert.strictEqual((await call('POST', '/api/send', { text: 'spam' }, sara.token)).status, 429);

  // Deleting: own message yes, other people's no, admin yes.
  const saraMsgId = s1.events.filter((e) => e.event === 'msg').pop().data.id;
  assert.strictEqual((await call('POST', '/api/delete', { id: saraMsgId }, ali.token)).status, 403);
  assert.strictEqual((await call('POST', '/api/delete', { id: saraMsgId }, sara.token)).status, 200);
  const delEv = await s1.next('delete');
  assert.strictEqual(delEv.data.id, saraMsgId);
  assert.strictEqual((await call('POST', '/api/delete', { id: sent.data.message.id }, admin.token)).status, 200);
  assert.strictEqual((await call('POST', '/api/delete', { id: 99999 }, admin.token)).status, 404);

  // Reconnecting with Last-Event-ID only replays what was missed.
  const lastId = Number(delEv.id);
  s1.close();
  const missed = await call('POST', '/api/send', { text: 'while you were away', cid: 'c2' }, admin.token);
  const s2 = openStream(sara.token, 0, lastId);
  const replay = [];
  replay.push(await s2.next('delete'));
  replay.push(await s2.next('msg'));
  assert.strictEqual(replay[1].data.id, missed.data.message.id);
  assert.ok(!s2.events.some((e) => e.event === 'reset'), 'should not resend full history');
  s2.close();

  // POST without JSON content type is refused (no cross-site form posts).
  const form = await fetch(BASE + '/api/send', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.strictEqual(form.status, 415);

  // Persistence across a restart.
  await stopServer();
  const saved = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'messages.json'), 'utf8'));
  await startServer();
  const s3 = openStream(sara.token);
  const reset2 = await s3.next('reset');
  assert.deepStrictEqual(reset2.data.messages.map((m) => m.id), saved.messages.map((m) => m.id));
  assert.ok(reset2.data.messages.some((m) => m.text === 'while you were away'));
  assert.ok(!reset2.data.messages.some((m) => m.id === saraMsgId), 'deleted message must stay deleted');
  // Tokens survive a restart (secret is stored in the data dir).
  assert.strictEqual((await call('GET', '/api/me', undefined, sara.token)).status, 200);
  s3.close();

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
