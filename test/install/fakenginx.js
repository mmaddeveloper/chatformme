// Stand-in for nginx on port 80: serves ACME challenge files like our nginx site would.
process.title = 'nginx';
const fs = require('fs');
require('http').createServer((req, res) => {
  const m = /^\/\.well-known\/acme-challenge\/([A-Za-z0-9_-]+)$/.exec(req.url);
  if (m) { try { return res.end(fs.readFileSync('/var/lib/chatformme-acme/.well-known/acme-challenge/' + m[1])); } catch (e) {} }
  res.statusCode = 404; res.end('nginx 404');
}).listen(80);
