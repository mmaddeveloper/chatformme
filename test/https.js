'use strict';

// HTTPS tests: TLS with a real certificate (made with openssl), certificate
// reload on SIGHUP, the plain-HTTP helper port (ACME challenge files and
// redirect to HTTPS) and the Secure cookie flag. Needs Node 18+ and openssl.

const assert = require('assert');
const http = require('http');
const https = require('https');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn, execFileSync } = require('child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'chatformme-https-'));
const certFile = path.join(dir, 'cert.pem');
const keyFile = path.join(dir, 'key.pem');
const webroot = path.join(dir, 'acme');
const port = 30000 + Math.floor(Math.random() * 15000);
const httpPort = port + 1;
let child;

function makeCert(cn) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-days', '30', '-subj', '/CN=' + cn, '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', keyFile, '-out', certFile], { stdio: 'ignore' });
}

function get(mod, options) {
  return new Promise((resolve, reject) => {
    const req = mod.request(options, (res) => {
      const cert = res.socket && res.socket.getPeerCertificate ? res.socket.getPeerCertificate() : null;
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body, cert }));
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function tls(pathname, extra) {
  // Verified against the test certificate; nothing here skips verification.
  return get(https, Object.assign({ host: '127.0.0.1', servername: 'localhost', port, path: pathname, ca: fs.readFileSync(certFile), agent: false }, extra || {}));
}

async function main() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
  } catch (e) {
    console.log('openssl not found; skipping HTTPS tests.');
    return;
  }
  makeCert('first');
  fs.mkdirSync(path.join(webroot, '.well-known', 'acme-challenge'), { recursive: true });
  fs.writeFileSync(path.join(webroot, '.well-known', 'acme-challenge', 'tok-123_A'), 'tok-123_A.keyauth');
  fs.writeFileSync(path.join(dir, 'secret.txt'), 'do not serve');

  child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: Object.assign({}, process.env, {
      PORT: String(port), HOST: '127.0.0.1', DATA_DIR: path.join(dir, 'data'), ADMIN_KEY: 'admin-secret-key',
      TLS_CERT: certFile, TLS_KEY: keyFile, HTTP_PORT: String(httpPort), ACME_WEBROOT: webroot,
      HTTPS_URL: 'https://localhost:' + port,
    }),
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  await new Promise((resolve, reject) => {
    const t = setInterval(() => { if (out.includes('is running')) { clearInterval(t); setTimeout(resolve, 200); } }, 50);
    child.on('exit', (code) => { clearInterval(t); reject(new Error('server exited ' + code + ': ' + out)); });
  });

  // HTTPS works and the certificate is the one we made.
  const cfg = await tls('/api/config');
  assert.strictEqual(cfg.status, 200);
  assert.strictEqual(cfg.cert.subject.CN, 'first');
  assert.strictEqual(cfg.headers['strict-transport-security'], undefined, 'HSTS is opt-in');

  // On HTTPS the session cookie is marked Secure.
  const reg = await tls('/api/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'تست', password: 'test-pass' }),
  });
  assert.strictEqual(reg.status, 200);
  assert.ok(/; Secure$/.test(reg.headers['set-cookie'][0]), reg.headers['set-cookie'][0]);

  // The HTTP helper port serves challenge files, nothing else, and redirects.
  const challenge = await get(http, { host: '127.0.0.1', port: httpPort, path: '/.well-known/acme-challenge/tok-123_A' });
  assert.deepStrictEqual([challenge.status, challenge.body], [200, 'tok-123_A.keyauth']);
  // Path tricks never reach other files (they end up as a 404 or a redirect).
  for (const bad of ['/.well-known/acme-challenge/../../secret.txt', '/.well-known/acme-challenge/%2e%2e%2fsecret.txt',
    '/.well-known/acme-challenge/..%2f..%2fsecret.txt', '/.well-known/acme-challenge/missing']) {
    const r = await get(http, { host: '127.0.0.1', port: httpPort, path: bad });
    assert.ok(r.status === 404 || r.status === 301, bad + ' -> ' + r.status);
    assert.ok(!r.body.includes('do not serve'), bad);
  }
  const redirect = await get(http, { host: '127.0.0.1', port: httpPort, path: '/some/page?x=1' });
  assert.strictEqual(redirect.status, 301);
  assert.strictEqual(redirect.headers.location, 'https://localhost:' + port + '/some/page?x=1');

  // A renewed certificate is picked up on SIGHUP without a restart.
  makeCert('second');
  child.kill('SIGHUP');
  await new Promise((r) => setTimeout(r, 300));
  const after = await tls('/api/config');
  assert.strictEqual(after.cert.subject.CN, 'second');
  assert.ok(out.includes('Reloaded the TLS certificate'));

  console.log('All HTTPS tests passed.');
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
}).finally(() => {
  if (child) child.kill('SIGTERM');
  setTimeout(() => fs.rmSync(dir, { recursive: true, force: true }), 300);
});
