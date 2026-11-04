#!/usr/bin/env node
'use strict';

// Usage: node port-owner.js PORT
// If a program listens on TCP PORT, prints "<program name> <pid>" and exits 0
// (name and pid are "?" when they cannot be determined); exits 1 when the port
// is free. Linux only: reads /proc, so it does not depend on ss or netstat.

const fs = require('fs');

const port = parseInt(process.argv[2], 10);
if (!(port > 0 && port < 65536)) {
  console.error('usage: port-owner.js PORT');
  process.exit(2);
}

const inodes = new Set();
for (const file of ['/proc/net/tcp', '/proc/net/tcp6']) {
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { continue; }
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || f[3] !== '0A') continue; // 0A = LISTEN
    if (parseInt(f[1].split(':').pop(), 16) === port) inodes.add(f[9]);
  }
}
if (!inodes.size) process.exit(1);

let owner = '? ?';
search:
for (const pid of fs.readdirSync('/proc')) {
  if (!/^\d+$/.test(pid)) continue;
  let fds;
  try { fds = fs.readdirSync('/proc/' + pid + '/fd'); } catch (e) { continue; }
  for (const fd of fds) {
    let link;
    try { link = fs.readlinkSync('/proc/' + pid + '/fd/' + fd); } catch (e) { continue; }
    const m = /^socket:\[(\d+)\]$/.exec(link);
    if (m && inodes.has(m[1])) {
      let name = '?';
      try { name = fs.readFileSync('/proc/' + pid + '/comm', 'utf8').trim() || '?'; } catch (e) { /* ignore */ }
      owner = name.replace(/\s+/g, '_') + ' ' + pid;
      break search;
    }
  }
}
console.log(owner);
