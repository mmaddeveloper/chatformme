'use strict';

// Tests for lib/store.js and for the server's use of it: durability across a
// crash, half-written journal lines, already-snapshotted entries, migration
// from the old conversations.json, and the single-server lock. Needs Node 18+.

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const crypto = require('crypto');
const { Store } = require('../lib/store');

const quiet = { log() {}, warn() {}, error() {} };
const tmpDirs = [];
function tmpDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chatformme-store-'));
  tmpDirs.push(dir);
  return path.join(dir, 'data'); // let the store create it
}

let msgN = 0;
function msgOp(store, conv, from, text) {
  const id = store.next();
  msgN += 1;
  return { op: 'msg', seq: id, m: { id, conv, from, uid: from === 'admin' ? 'admin1' : conv, name: 'n' + conv, text: text || 'm' + msgN, ts: Date.now() } };
}

function snapshotOf(store) {
  return JSON.parse(JSON.stringify({ seq: store.seq, convs: store.convs }));
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

function unitTests() {
  // Reopening replays the journal into the same state.
  const dir = tmpDir();
  let s = new Store(dir, { log: quiet }).open();
  s.commit(msgOp(s, 'a', 'visitor', 'سلام'));
  s.commit(msgOp(s, 'a', 'admin', 'درود'));
  s.commit(msgOp(s, 'b', 'visitor'));
  s.commit({ op: 'read', seq: s.next(), conv: 'b', adminRead: s.get('b').messages[0].id });
  s.commit({ op: 'rename', seq: s.next(), conv: 'a', name: 'علی' });
  s.commit({ op: 'del', seq: s.next(), conv: 'a', id: s.get('a').messages[1].id });
  const before = snapshotOf(s);
  s.close();
  assert.strictEqual(fs.existsSync(path.join(dir, 'lock')), false, 'lock released on close');
  s = new Store(dir, { log: quiet }).open();
  assert.deepStrictEqual(snapshotOf(s), before);
  assert.strictEqual(s.get('a').name, 'علی');
  assert.strictEqual(s.get('b').adminRead, s.get('b').messages[0].id);
  assert.strictEqual(s.get('__proto__'), null);
  s.close();

  // A half-written last line (power cut mid-write) is dropped, and later
  // writes start on a clean line.
  fs.appendFileSync(path.join(dir, 'journal.log'), '{"op":"msg","seq":999,"m":{"id":99');
  const warnings = [];
  s = new Store(dir, { log: { log() {}, error() {}, warn: (w) => warnings.push(w) } }).open();
  assert.ok(warnings.some((w) => /incomplete last entry/.test(w)));
  assert.deepStrictEqual(snapshotOf(s), before);
  s.commit(msgOp(s, 'c', 'visitor', 'after crash'));
  const afterCrash = snapshotOf(s);
  s.close();
  s = new Store(dir, { log: quiet }).open();
  assert.deepStrictEqual(snapshotOf(s), afterCrash);
  s.close();

  // Crash after writing a snapshot but before emptying the journal: the
  // entries already in the snapshot are not applied twice.
  const dir2 = tmpDir();
  s = new Store(dir2, { log: quiet }).open();
  for (let i = 0; i < 5; i++) s.commit(msgOp(s, 'x', 'visitor'));
  const journal = fs.readFileSync(path.join(dir2, 'journal.log'));
  s.compact();
  fs.appendFileSync(path.join(dir2, 'journal.log'), journal);
  const compacted = snapshotOf(s);
  s.close();
  s = new Store(dir2, { log: quiet }).open();
  assert.deepStrictEqual(snapshotOf(s), compacted);
  assert.strictEqual(s.get('x').messages.length, 5);
  assert.strictEqual(fs.statSync(path.join(dir2, 'journal.log')).size, 0, 'stale entries are compacted away');
  s.close();

  // The journal is folded into a snapshot once it grows past the limit.
  const dir3 = tmpDir();
  s = new Store(dir3, { log: quiet, compactBytes: 2000 }).open();
  for (let i = 0; i < 30; i++) s.commit(msgOp(s, 'y', 'visitor', 'x'.repeat(50)));
  assert.ok(fs.statSync(path.join(dir3, 'journal.log')).size < 2000);
  assert.ok(fs.existsSync(path.join(dir3, 'snapshot.json')));
  const big = snapshotOf(s);
  s.close();
  s = new Store(dir3, { log: quiet, compactBytes: 2000 }).open();
  assert.deepStrictEqual(snapshotOf(s), big);
  s.close();

  // Conversations are capped by message count and by size; totals add up.
  const dir4 = tmpDir();
  s = new Store(dir4, { log: quiet, maxHistory: 3, maxConvBytes: 1000000 }).open();
  for (let i = 0; i < 5; i++) s.commit(msgOp(s, 'z', 'visitor', 'n' + i));
  assert.deepStrictEqual(s.get('z').messages.map((m) => m.text), ['n2', 'n3', 'n4']);
  s.close();
  s = new Store(dir4, { log: quiet, maxHistory: 300, maxConvBytes: 5000 }).open();
  for (let i = 0; i < 5; i++) s.commit(msgOp(s, 'w', 'visitor', 'y'.repeat(1000)));
  assert.ok(s.get('w').bytes <= 5000 && s.get('w').messages.length >= 1);
  const sum = s.uids().reduce((t, uid) => t + s.get(uid).bytes, 0);
  assert.strictEqual(s.totalBytes, sum);
  s.commit({ op: 'convdel', seq: s.next(), conv: 'w' });
  assert.strictEqual(s.totalBytes, s.get('z').bytes);
  s.close();

  // Accounts are stored and survive a restart; usernames stay unique.
  const dir5 = tmpDir();
  s = new Store(dir5, { log: quiet }).open();
  s.commit({ op: 'account', seq: s.next(), uid: 'u1', name: 'Sara', key: 'sara', salt: 's1', hash: 'h1', created: 1 });
  assert.throws(() => s.commit({ op: 'account', seq: s.next(), uid: 'u2', name: 'sara', key: 'sara', salt: 's', hash: 'h', created: 2 }));
  s.commit(msgOp(s, 'u1', 'visitor', 'hi'));
  s.commit({ op: 'passwd', seq: s.next(), uid: 'u1', salt: 's2', hash: 'h2', v: 2 });
  s.compact();
  s.commit({ op: 'account', seq: s.next(), uid: 'u3', name: 'Reza', key: 'reza', salt: 's3', hash: 'h3', created: 3 });
  s.close();
  s = new Store(dir5, { log: quiet }).open();
  assert.deepStrictEqual([s.account('u1').hash, s.account('u1').v], ['h2', 2]);
  assert.strictEqual(s.accountByKey('reza').uid, 'u3');
  assert.strictEqual(s.accountByKey('__proto__'), null);
  // Automatic clean-up keeps the account; an admin removing the person does not.
  s.commit({ op: 'convdel', seq: s.next(), conv: 'u1' });
  assert.ok(s.account('u1'));
  s.commit({ op: 'convdel', seq: s.next(), conv: 'u1', account: true });
  assert.strictEqual(s.account('u1'), null);
  assert.strictEqual(s.accountByKey('sara'), null);
  s.close();
  s = new Store(dir5, { log: quiet }).open();
  assert.strictEqual(s.accountCount(), 1);
  s.close();

  // Files are private.
  assert.strictEqual(fs.statSync(dir).mode & 0o777, 0o700);
  assert.strictEqual(fs.statSync(path.join(dir, 'journal.log')).mode & 0o777, 0o600);
}

// ---------------------------------------------------------------------------
// Server tests
// ---------------------------------------------------------------------------

const SERVER = path.join(__dirname, '..', 'server.js');

function runServer(dataDir, env) {
  const port = 30000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [SERVER], {
    env: Object.assign({}, process.env, { PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, ADMIN_KEY: 'admin-secret-key' }, env || {}),
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  const ready = new Promise((resolve, reject) => {
    const timer = setInterval(() => { if (out.includes('is running')) { clearInterval(timer); resolve(); } }, 50);
    child.on('exit', (code) => { clearInterval(timer); reject(Object.assign(new Error('exited ' + code + ': ' + out), { code, out })); });
  });
  return { child, port, ready, output: () => out, base: 'http://127.0.0.1:' + port };
}

function exited(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    child.on('exit', (code, signal) => resolve(code === null ? signal : code));
  });
}

async function post(base, url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const res = await fetch(base + url, { method: 'POST', headers, body: JSON.stringify(body) });
  return { status: res.status, data: await res.json() };
}

async function serverTests() {
  // A message is durable as soon as the server has answered, even if the
  // process is killed right after.
  const dataDir = tmpDir();
  let srv = runServer(dataDir);
  await srv.ready;
  const visitor = (await post(srv.base, '/api/register', { username: 'سارا', password: 'sara-pass' })).data;
  const sent = await post(srv.base, '/api/send', { text: 'پیام مهم' }, visitor.token);
  assert.strictEqual(sent.status, 200);
  srv.child.kill('SIGKILL');
  await exited(srv.child);

  // The lock left behind by the killed server does not block a restart...
  srv = runServer(dataDir);
  await srv.ready;
  const admin = (await post(srv.base, '/api/admin/login', { name: 'مدیر', key: 'admin-secret-key' })).data;
  const conv = await fetch(srv.base + '/api/conversation?conv=' + visitor.user.uid, { headers: { Authorization: 'Bearer ' + admin.token } });
  assert.strictEqual(conv.status, 200);
  assert.deepStrictEqual((await conv.json()).messages.map((m) => m.text), ['پیام مهم']);

  // ...but a second server on the same data refuses to start.
  const second = runServer(dataDir);
  const err = await second.ready.then(() => null, (e) => e);
  assert.ok(err && err.code === 1, 'second server must exit');
  assert.ok(/already using/.test(err.out), err && err.out);
  srv.child.kill('SIGTERM');
  await exited(srv.child);

  // Data from the previous format is migrated on first start.
  const legacyDir = tmpDir();
  fs.mkdirSync(legacyDir, { recursive: true });
  fs.writeFileSync(path.join(legacyDir, 'conversations.json'), JSON.stringify({
    seq: 2,
    convs: {
      oldvisitor: {
        uid: 'oldvisitor', name: 'رضا', created: 1, adminRead: 0, visitorRead: 2,
        messages: [
          { id: 1, conv: 'oldvisitor', from: 'visitor', uid: 'oldvisitor', name: 'رضا', text: 'قدیمی ۱', ts: 1 },
          { id: 2, conv: 'oldvisitor', from: 'visitor', uid: 'oldvisitor', name: 'رضا', text: 'قدیمی ۲', ts: 2 },
        ],
      },
    },
  }));
  fs.copyFileSync(path.join(dataDir, 'secret.key'), path.join(legacyDir, 'secret.key'));
  srv = runServer(legacyDir);
  await srv.ready;
  assert.ok(/Moved 1 conversations/.test(srv.output()));
  assert.ok(fs.existsSync(path.join(legacyDir, 'snapshot.json')));
  assert.ok(fs.existsSync(path.join(legacyDir, 'conversations.json.migrated')));
  const migrated = await fetch(srv.base + '/api/conversation?conv=oldvisitor', { headers: { Authorization: 'Bearer ' + admin.token } });
  assert.deepStrictEqual((await migrated.json()).messages.map((m) => m.text), ['قدیمی ۱', 'قدیمی ۲']);
  // New ids continue after the migrated ones.
  const reply = await post(srv.base, '/api/send', { text: 'جدید', conv: 'oldvisitor' }, admin.token);
  assert.strictEqual(reply.data.message.id, 3);

  // The visitor of an old conversation (from before accounts existed) still
  // has its session on their phone; that session alone no longer gets in...
  const secret = fs.readFileSync(path.join(legacyDir, 'secret.key'), 'utf8').trim();
  const key = crypto.createHash('sha256').update(secret + '\0' + '' + '\0' + 'admin-secret-key').digest();
  const b64 = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const payload = b64(JSON.stringify({ u: 'oldvisitor', n: 'رضا', a: 0, t: Date.now() }));
  const legacyToken = payload + '.' + b64(crypto.createHmac('sha256', key).update(payload).digest());
  const me = await fetch(srv.base + '/api/me', { headers: { Authorization: 'Bearer ' + legacyToken } });
  assert.strictEqual(me.status, 401);
  // ...but choosing a username and password keeps their conversation.
  const claimed = await post(srv.base, '/api/register', { username: 'رضا', password: 'reza-pass', prevToken: legacyToken });
  assert.strictEqual(claimed.data.user.uid, 'oldvisitor');
  const again = await post(srv.base, '/api/register', { username: 'رضا۲', password: 'reza-pass', prevToken: legacyToken });
  assert.notStrictEqual(again.data.user.uid, 'oldvisitor', 'a conversation can only be claimed once');
  srv.child.kill('SIGTERM');
  await exited(srv.child);

  // A short admin key is refused at start.
  const weak = runServer(tmpDir(), { ADMIN_KEY: 'short' });
  const weakErr = await weak.ready.then(() => null, (e) => e);
  assert.ok(weakErr && /too short/.test(weakErr.out));
}

(async () => {
  unitTests();
  await serverTests();
  console.log('All storage tests passed.');
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
}).finally(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
});
