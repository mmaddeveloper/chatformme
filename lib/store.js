'use strict';

// Durable, dependency-free storage for conversations.
//
// Files in the data directory (all private to the server's user):
//   snapshot.json  the full state at some moment, written atomically and fsync'd
//   journal.log    every change since that snapshot, one JSON line each, append-only
//   lock           pid of the server process using this directory
//
// A change is written to the journal before it is applied in memory, and the
// journal is flushed to disk within a fraction of a second. On start the
// snapshot is loaded and the journal replayed; a half-written last line (crash
// or power cut mid-write) is detected and dropped. When the journal grows past
// a limit it is folded into a new snapshot. Every change carries a sequence
// number, so replaying entries that are already in the snapshot (a crash
// between writing the snapshot and emptying the journal) changes nothing.
//
// The previous format (a single conversations.json rewritten every second) is
// migrated automatically on first start.

const fs = require('fs');
const path = require('path');

const FORMAT = 2;
const MESSAGE_OVERHEAD = 160; // rough per-message memory besides its text

function messageSize(m) {
  return MESSAGE_OVERHEAD + 2 * (String(m.text).length + String(m.name).length);
}

function readText(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch (e) { return ''; }
}

// Is `pid` a running chatformme server (and not some unrelated process that
// happens to have reused the pid of one that crashed)?
function isServerProcess(pid) {
  try {
    process.kill(pid, 0);
  } catch (e) {
    if (e.code === 'ESRCH') return false;
  }
  try {
    return fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').indexOf('server.js') !== -1;
  } catch (e) {
    return true; // cannot tell: assume it is, rather than risk two writers
  }
}

function syncDir(dir) {
  let fd = null;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch (e) {
    // Not supported on every platform; the rename is still atomic.
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

class Store {
  constructor(dir, options) {
    options = options || {};
    this.dir = dir;
    this.maxHistory = options.maxHistory || 300;
    this.maxConvBytes = options.maxConvBytes || 256 * 1024;
    this.compactBytes = options.compactBytes || 4 * 1024 * 1024;
    this.log = options.log || console;
    this.files = {
      snapshot: path.join(dir, 'snapshot.json'),
      journal: path.join(dir, 'journal.log'),
      lock: path.join(dir, 'lock'),
      legacy: path.join(dir, 'conversations.json'),
    };
    this.seq = 0;
    this.convs = Object.create(null); // uid -> conversation; no prototype keys
    this.totalBytes = 0;
    this.fd = null;
    this.journalBytes = 0;
    this.syncTimer = null;
    this.locked = false;
  }

  // ---- lifecycle -----------------------------------------------------------

  open() {
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    // Older installs created these readable by every user on the machine.
    try { fs.chmodSync(this.dir, 0o700); } catch (e) { /* not ours to change */ }
    for (const name of fs.readdirSync(this.dir)) {
      try { fs.chmodSync(path.join(this.dir, name), 0o600); } catch (e) { /* ignore */ }
    }
    this.lock();
    const snapshotSeq = this.loadSnapshot();
    const hasStale = this.replayJournal(snapshotSeq);
    this.fd = fs.openSync(this.files.journal, 'a', 0o600);
    if (hasStale || this.journalBytes > this.compactBytes) this.compact();
    return this;
  }

  close() {
    if (this.fd !== null) {
      clearTimeout(this.syncTimer);
      this.syncTimer = null;
      try { fs.fsyncSync(this.fd); } catch (e) { /* ignore */ }
      fs.closeSync(this.fd);
      this.fd = null;
    }
    if (this.locked) {
      try { fs.unlinkSync(this.files.lock); } catch (e) { /* ignore */ }
      this.locked = false;
    }
  }

  lock() {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = fs.openSync(this.files.lock, 'wx', 0o600);
        fs.writeSync(fd, String(process.pid));
        fs.closeSync(fd);
        this.locked = true;
        return;
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        const pid = parseInt(readText(this.files.lock), 10);
        if (pid && pid !== process.pid && isServerProcess(pid)) {
          throw new Error('another chatformme server (pid ' + pid + ') is already using ' + this.dir);
        }
        fs.unlinkSync(this.files.lock); // left behind by a server that crashed
      }
    }
    throw new Error('could not lock ' + this.dir);
  }

  // ---- loading -------------------------------------------------------------

  loadSnapshot() {
    let file = null;
    if (fs.existsSync(this.files.snapshot)) file = this.files.snapshot;
    else if (fs.existsSync(this.files.legacy)) file = this.files.legacy;
    if (!file) return 0;

    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (!raw || typeof raw.convs !== 'object' || !raw.convs) throw new Error('unexpected format');
    } catch (err) {
      // Never silently overwrite a file we could not read.
      const backup = file + '.corrupt-' + Date.now();
      fs.renameSync(file, backup);
      this.log.error('Could not read ' + file + ' (' + err.message + '); moved it to ' + backup);
      return 0;
    }

    this.seq = Number(raw.seq) || 0;
    for (const uid of Object.keys(raw.convs)) {
      const c = raw.convs[uid];
      if (!c || !Array.isArray(c.messages)) continue;
      const conv = this.makeConv(uid, String(c.name || ''), Number(c.created) || Date.now());
      conv.adminRead = Number(c.adminRead) || 0;
      conv.visitorRead = Number(c.visitorRead) || 0;
      for (const m of c.messages) if (m && typeof m.text === 'string') this.pushMessage(conv, m);
    }

    if (file === this.files.legacy) {
      this.writeSnapshot();
      fs.renameSync(this.files.legacy, this.files.legacy + '.migrated');
      this.log.log('Moved ' + Object.keys(this.convs).length + ' conversations from conversations.json to the new storage format.');
    }
    return this.seq;
  }

  // Returns true when the journal holds entries already in the snapshot.
  replayJournal(snapshotSeq) {
    let buf;
    try {
      buf = fs.readFileSync(this.files.journal);
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      throw err;
    }
    const end = buf.lastIndexOf(10) + 1; // everything up to the last newline
    if (end !== buf.length) {
      fs.truncateSync(this.files.journal, end);
      this.log.warn('Dropped an incomplete last entry from ' + this.files.journal + ' (the server stopped mid-write).');
    }
    let stale = 0;
    let bad = 0;
    for (const line of buf.slice(0, end).toString('utf8').split('\n')) {
      if (!line) continue;
      let op;
      try { op = JSON.parse(line); } catch (e) { bad += 1; continue; }
      if (!op || typeof op.seq !== 'number') { bad += 1; continue; }
      if (op.seq <= snapshotSeq) { stale += 1; continue; }
      try { this.apply(op); } catch (e) { bad += 1; }
    }
    if (bad) this.log.warn('Skipped ' + bad + ' unreadable entries in ' + this.files.journal + '.');
    this.journalBytes = end;
    return stale > 0;
  }

  // ---- reading ---------------------------------------------------------------

  get(uid) {
    return typeof uid === 'string' && Object.prototype.hasOwnProperty.call(this.convs, uid) ? this.convs[uid] : null;
  }

  uids() {
    return Object.keys(this.convs);
  }

  next() {
    this.seq += 1;
    return this.seq;
  }

  // ---- writing ---------------------------------------------------------------

  // Durably record one change, then apply it in memory.
  commit(op) {
    const line = JSON.stringify(op) + '\n';
    try {
      fs.writeSync(this.fd, line);
    } catch (err) {
      // Do not leave half a line behind (for example when the disk is full).
      try { fs.ftruncateSync(this.fd, this.journalBytes); } catch (e) { /* ignore */ }
      throw err;
    }
    this.journalBytes += Buffer.byteLength(line);
    this.apply(op);
    this.scheduleSync();
    if (this.journalBytes > this.compactBytes) this.compact();
  }

  apply(op) {
    switch (op.op) {
      case 'msg': {
        const m = op.m;
        const conv = this.get(m.conv) || this.makeConv(m.conv, m.name, m.ts);
        this.pushMessage(conv, m);
        // Whoever writes has obviously seen the conversation.
        if (m.from === 'admin') {
          conv.adminRead = m.id;
        } else {
          conv.visitorRead = m.id;
          conv.name = m.name;
        }
        break;
      }
      case 'del': {
        const conv = this.get(op.conv);
        const idx = conv ? conv.messages.findIndex((m) => m.id === op.id) : -1;
        if (idx !== -1) this.dropMessage(conv, idx);
        break;
      }
      case 'read': {
        const conv = this.get(op.conv);
        if (conv && typeof op.adminRead === 'number') conv.adminRead = op.adminRead;
        if (conv && typeof op.visitorRead === 'number') conv.visitorRead = op.visitorRead;
        break;
      }
      case 'rename': {
        const conv = this.get(op.conv);
        if (conv) conv.name = String(op.name);
        break;
      }
      case 'convdel': {
        const conv = this.get(op.conv);
        if (conv) {
          this.totalBytes -= conv.bytes;
          delete this.convs[op.conv];
        }
        break;
      }
      default:
        throw new Error('unknown operation ' + op.op);
    }
    if (op.seq > this.seq) this.seq = op.seq;
  }

  makeConv(uid, name, created) {
    const conv = { uid: uid, name: name, created: created, messages: [], adminRead: 0, visitorRead: 0 };
    // Not enumerable, so it is not written into the snapshot.
    Object.defineProperty(conv, 'bytes', { value: 0, writable: true, enumerable: false });
    this.convs[uid] = conv;
    return conv;
  }

  pushMessage(conv, m) {
    conv.messages.push(m);
    const size = messageSize(m);
    conv.bytes += size;
    this.totalBytes += size;
    // Keep each conversation bounded; the newest message always stays.
    while (conv.messages.length > 1 && (conv.messages.length > this.maxHistory || conv.bytes > this.maxConvBytes)) {
      this.dropMessage(conv, 0);
    }
  }

  dropMessage(conv, idx) {
    const size = messageSize(conv.messages[idx]);
    conv.messages.splice(idx, 1);
    conv.bytes -= size;
    this.totalBytes -= size;
  }

  scheduleSync() {
    if (this.syncTimer) return;
    this.syncTimer = setTimeout(() => {
      this.syncTimer = null;
      try {
        fs.fdatasyncSync(this.fd);
      } catch (err) {
        this.log.error('Flushing the journal to disk failed: ' + err.message);
      }
    }, 200);
    if (this.syncTimer.unref) this.syncTimer.unref();
  }

  // Fold the journal into a fresh snapshot and start an empty journal.
  compact() {
    this.writeSnapshot();
    fs.ftruncateSync(this.fd, 0);
    fs.fsyncSync(this.fd);
    this.journalBytes = 0;
  }

  writeSnapshot() {
    const tmp = this.files.snapshot + '.tmp';
    const data = JSON.stringify({ format: FORMAT, seq: this.seq, convs: this.convs });
    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.files.snapshot);
    syncDir(this.dir);
  }
}

module.exports = { Store: Store };
