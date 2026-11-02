(function () {
  'use strict';

  // Two views share this page:
  //  - visitors: one private conversation with the site's admins;
  //  - admins: an inbox of every conversation, and the open conversation.

  // ---------- small helpers ----------

  var $ = function (id) { return document.getElementById(id); };
  var SVG_NS = 'http://www.w3.org/2000/svg';

  var storage = {
    get: function (k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
    del: function (k) { try { window.localStorage.removeItem(k); } catch (e) { /* ignore */ } }
  };

  function readJson(key) {
    try { return JSON.parse(storage.get(key) || 'null'); } catch (e) { return null; }
  }

  function randomId() {
    var bytes = new Uint8Array(12);
    (window.crypto || window.msCrypto).getRandomValues(bytes);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
    return s;
  }

  function makeFormat(Ctor, opts) {
    try { return new Ctor('fa-IR', opts); } catch (e) { return null; }
  }
  var fmtNum = makeFormat(Intl.NumberFormat);
  var fmtTime = makeFormat(Intl.DateTimeFormat, { hour: '2-digit', minute: '2-digit' });
  var fmtShortDate = makeFormat(Intl.DateTimeFormat, { day: 'numeric', month: 'short' });
  var fmtLongDate = makeFormat(Intl.DateTimeFormat, { weekday: 'long', day: 'numeric', month: 'long' });

  function faNum(n) {
    return fmtNum ? fmtNum.format(n) : String(n);
  }
  function faCount(n) {
    return n > 99 ? faNum(99) + '+' : faNum(n);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function icon(id, className) {
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    if (className) svg.setAttribute('class', className);
    var use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', '#' + id);
    svg.appendChild(use);
    return svg;
  }

  // Stable color (0-7) and initial for each person.
  function colorClass(uid) {
    var h = 0;
    uid = String(uid || '');
    for (var i = 0; i < uid.length; i++) h = (h * 31 + uid.charCodeAt(i)) >>> 0;
    return 'c' + (h % 8);
  }
  var segmenter = window.Intl && Intl.Segmenter ? new Intl.Segmenter() : null;
  function initial(name) {
    var text = String(name || '').trim();
    if (!text) return '?';
    var first = segmenter ? segmenter.segment(text)[Symbol.iterator]().next().value.segment : Array.from(text)[0];
    return first.toUpperCase();
  }
  function setAvatar(node, uid, name, online) {
    node.className = 'avatar ' + colorClass(uid) + (online ? ' online' : '');
    node.textContent = initial(name);
    node.setAttribute('aria-hidden', 'true');
    return node;
  }

  var ERRORS = {
    bad_password: 'رمز اشتباه است.',
    bad_name: 'نام باید بین ۱ تا ۳۲ حرف باشد.',
    rate_limited: 'درخواست‌ها زیاد است؛ چند لحظه صبر کنید.',
    too_long: 'پیام خیلی طولانی است.',
    empty: 'پیام خالی است.',
    forbidden: 'اجازهٔ این کار را ندارید.',
    not_found: 'پیدا نشد (شاید حذف شده).',
    network: 'ارتباط با سرور برقرار نشد. اتصال را بررسی کنید.',
    server_error: 'خطای سرور؛ دوباره تلاش کنید.'
  };
  function errorText(err) {
    return ERRORS[err.code] || (err.status ? ERRORS.server_error : ERRORS.network);
  }

  // ---------- state ----------

  var state = {
    config: { passwordRequired: false, adminEnabled: false, maxMessageLength: 2000 },
    token: storage.get('chat.token'),
    user: readJson('chat.user'),
    es: null,
    connState: 'connecting',
    lastSeq: 0,
    lastEventAt: 0,
    reconnectTimer: null,
    reconnectDelay: 2000,
    pending: {},        // cid -> { text, conv, li, tries, timer }
    unread: 0,          // visitor: unseen replies, for the tab title
    unseen: 0,          // for the "new messages" button
    baseTitle: document.title,
    // visitor
    adminsOnline: 0,
    adminRead: 0,       // last of my messages the admins have seen
    lastReplyId: 0,     // newest admin reply shown
    readSent: 0,
    // admin
    convs: {},          // visitor uid -> summary
    onlineVisitors: {}, // visitor uid -> true
    openConv: null,
    openLoaded: false,
    openBuffer: []
  };

  function isAdmin() { return !!(state.user && state.user.admin); }

  var isTouch = window.matchMedia && window.matchMedia('(hover: none) and (pointer: coarse)').matches;

  // On phones the on-screen keyboard shrinks the visible area; size the app to it
  // so the message box always stays visible above the keyboard (mainly iOS).
  if (window.visualViewport) {
    var vv = window.visualViewport;
    var fitViewport = function () {
      if (vv.scale > 1.01) return; // pinch-zoomed: leave the layout alone
      document.documentElement.style.setProperty('--app-h', Math.round(vv.height) + 'px');
      if (window.scrollY) window.scrollTo(0, 0);
    };
    vv.addEventListener('resize', fitViewport);
    fitViewport();
  }

  // ---------- API ----------

  function api(method, url, body, timeoutMs) {
    var opts = { method: method, headers: {}, cache: 'no-store' };
    if (state.token) opts.headers.Authorization = 'Bearer ' + state.token;
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    var timer = null;
    if (window.AbortController) {
      var ctrl = new AbortController();
      opts.signal = ctrl.signal;
      timer = setTimeout(function () { ctrl.abort(); }, timeoutMs || 15000);
    }
    return fetch(url, opts).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (data) {
        if (timer) clearTimeout(timer);
        if (!res.ok) {
          var err = new Error((data && data.error) || 'http_' + res.status);
          err.status = res.status;
          err.code = data && data.error;
          throw err;
        }
        return data;
      });
    }, function () {
      if (timer) clearTimeout(timer);
      var err = new Error('network');
      err.code = 'network';
      throw err;
    });
  }

  // ---------- join screen ----------

  function showJoin(message) {
    closeStream();
    $('chat').hidden = true;
    $('join').hidden = false;
    setConn('online');
    document.title = state.baseTitle;
    var lastName = storage.get('chat.name');
    if (lastName && !$('name').value) $('name').value = lastName;
    $('password-row').hidden = !state.config.passwordRequired;
    $('admin-toggle').hidden = state.config.passwordRequired || !state.config.adminEnabled;
    showJoinError(message || '');
    if (!isTouch) setTimeout(function () { $('name').focus(); }, 0);
  }

  function showJoinError(text) {
    $('join-error').textContent = text;
    $('join-error').hidden = !text;
  }

  $('admin-toggle').addEventListener('click', function () {
    $('password-label').textContent = 'کلید مدیر';
    $('password-row').hidden = false;
    $('admin-toggle').hidden = true;
    $('join-btn').textContent = 'ورود';
    $('password').focus();
  });

  $('join-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var name = $('name').value.trim();
    if (!name) { showJoinError(ERRORS.bad_name); $('name').focus(); return; }
    var btn = $('join-btn');
    btn.disabled = true;
    showJoinError('');
    var body = { name: name, password: $('password').value, prevToken: storage.get('chat.prevToken') || undefined };
    var oldToken = state.token;
    state.token = null; // never send a stale token while joining
    api('POST', '/api/join', body).then(function (data) {
      state.token = data.token;
      state.user = data.user;
      storage.set('chat.token', data.token);
      storage.set('chat.prevToken', data.token);
      storage.set('chat.user', JSON.stringify(data.user));
      storage.set('chat.name', data.user.name);
      $('password').value = '';
      startApp();
    }, function (err) {
      state.token = oldToken;
      showJoinError(errorText(err));
    }).then(function () { btn.disabled = false; });
  });

  // ---------- app shell ----------

  var app = $('chat');
  var list = $('messages');
  var input = $('input');
  var sendBtn = $('send-btn');

  function startApp() {
    $('join').hidden = true;
    app.hidden = false;
    app.classList.toggle('is-admin', isAdmin());
    app.classList.toggle('is-visitor', !isAdmin());
    list.innerHTML = '';
    state.lastSeq = 0;
    state.convs = {};
    convNodes = {};
    $('conv-list').innerHTML = '';
    state.openConv = null;
    state.adminRead = 0;
    state.lastReplyId = 0;
    state.readSent = 0;
    state.unread = 0;
    app.classList.remove('conv-open');
    $('conv-delete').hidden = !isAdmin();
    $('visitor-logout').hidden = isAdmin();
    if (isAdmin()) {
      setAvatar($('me-avatar'), state.user.uid, state.user.name);
      $('me-name').textContent = state.user.name;
      input.placeholder = 'پاسخ…';
      renderConvList();
    } else {
      input.placeholder = 'پیام خود را بنویسید…';
      relayout();
    }
    renderTopbar();
    connect();
    updateSendButton();
    if (!isAdmin() && !isTouch) input.focus();
  }

  function logout() {
    closeStream();
    var ids = Object.keys(state.pending);
    for (var i = 0; i < ids.length; i++) clearTimeout(state.pending[ids[i]].timer);
    state.pending = {};
    state.token = null;
    state.user = null;
    storage.del('chat.token');
    storage.del('chat.user');
    list.innerHTML = '';
    $('conv-list').innerHTML = '';
    showJoin();
  }

  function confirmLogout() {
    var msg = isAdmin() ? 'از حساب مدیر خارج می‌شوید؟'
      : 'خارج می‌شوید؟ با ورود دوباره از همین دستگاه، گفتگوی شما سر جایش است.';
    if (window.confirm(msg)) logout();
  }
  $('logout-btn').addEventListener('click', confirmLogout);
  $('visitor-logout').addEventListener('click', confirmLogout);

  function handleUnauthorized() {
    logout();
    showJoinError('نشست شما منقضی شده یا رمز تغییر کرده؛ لطفاً دوباره وارد شوید.');
  }

  function renderTopbar() {
    var status = $('status');
    var text;
    var online = false;
    if (isAdmin()) {
      var c = state.convs[state.openConv];
      if (!c) return;
      online = !!state.onlineVisitors[c.uid];
      $('chat-title').textContent = c.name;
      $('chat-title').title = c.name;
      setAvatar($('top-avatar'), c.uid, c.name, online);
      $('top-avatar').hidden = false;
      text = online ? 'آنلاین' : 'آفلاین';
    } else {
      $('chat-title').textContent = state.baseTitle;
      $('chat-title').title = state.baseTitle;
      online = state.adminsOnline > 0;
      text = online ? 'پاسخگو آنلاین است' : 'پاسخگو الان آنلاین نیست؛ پیام شما می‌رسد';
    }
    status.setAttribute('data-state', online ? 'online' : 'away');
    $('status-text').textContent = text;
  }

  function updateTitle() {
    var n = 0;
    if (isAdmin()) {
      var ids = Object.keys(state.convs);
      for (var i = 0; i < ids.length; i++) n += state.convs[ids[i]].unread;
    } else {
      n = state.unread;
    }
    document.title = (n ? '(' + faNum(n) + ') ' : '') + state.baseTitle;
  }

  // ---------- connection (Server-Sent Events) ----------

  var connTimer = null;
  function setConn(s) {
    state.connState = s;
    var box = $('conn');
    clearTimeout(connTimer);
    if (s === 'online') { box.hidden = true; return; }
    box.setAttribute('data-state', s);
    box.textContent = s === 'offline' ? 'اتصال قطع است؛ تلاش دوباره…' : 'در حال اتصال…';
    // Short blips are normal; only show the notice if it lasts a moment.
    connTimer = setTimeout(function () { if (state.token) box.hidden = false; }, 1500);
  }

  function closeStream() {
    if (state.es) { state.es.close(); state.es = null; }
    if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
  }

  function connect() {
    closeStream();
    if (!state.token) return;
    setConn('connecting');
    var url = '/api/stream?token=' + encodeURIComponent(state.token) + '&since=' + state.lastSeq;
    var es = new EventSource(url);
    state.es = es;
    state.lastEventAt = Date.now();

    function on(type, handler) {
      es.addEventListener(type, function (e) {
        state.lastEventAt = Date.now();
        if (e.lastEventId) {
          var n = parseInt(e.lastEventId, 10);
          if (type === 'reset' || n > state.lastSeq) state.lastSeq = n || 0;
        }
        if (handler) handler(e.data ? JSON.parse(e.data) : null);
      });
    }

    es.onopen = function () {
      state.reconnectDelay = 2000;
      state.lastEventAt = Date.now();
      setConn('online');
    };
    on('ping');
    if (isAdmin()) {
      on('reset', adminReset);
      on('msg', adminMsg);
      on('delete', adminDelete);
      on('read', adminReadEvent);
      on('convdelete', adminConvDelete);
      on('presence', adminPresence);
    } else {
      on('reset', visitorReset);
      on('msg', function (d) { visitorMsg(d.message); });
      on('delete', function (d) { removeMessage(d.id); });
      on('read', function (d) { state.adminRead = d.adminRead; updateTicks(); });
      on('convdelete', function () {
        state.adminRead = 0;
        state.lastReplyId = 0;
        state.readSent = 0;
        renderAll([]);
      });
      on('presence', function (d) { state.adminsOnline = d.admins; renderTopbar(); });
    }
    es.onerror = function () {
      if (es !== state.es) return;
      if (es.readyState === 2 /* CLOSED */) {
        // The browser gave up (bad token, server full, ...). Find out why.
        setConn('offline');
        api('GET', '/api/me').then(scheduleReconnect, function (err) {
          if (err.status === 401) handleUnauthorized(); else scheduleReconnect();
        });
      } else {
        setConn('connecting'); // the browser reconnects by itself
      }
    };
  }

  function scheduleReconnect() {
    if (!state.token || state.reconnectTimer) return;
    if (state.es) { state.es.close(); state.es = null; }
    setConn('offline');
    state.reconnectTimer = setTimeout(function () {
      state.reconnectTimer = null;
      connect();
    }, state.reconnectDelay);
    state.reconnectDelay = Math.min(state.reconnectDelay * 2, 30000);
  }

  // Mobile networks sometimes leave a dead connection open. The server sends a
  // ping every 25 seconds; if nothing arrives for a while, reconnect.
  setInterval(function () {
    if (state.es && Date.now() - state.lastEventAt > 70000) {
      state.reconnectDelay = 1000;
      scheduleReconnect();
    }
  }, 10000);

  window.addEventListener('online', function () {
    if (state.token && (!state.es || state.es.readyState === 2)) {
      state.reconnectDelay = 1000;
      closeStream();
      connect();
    }
  });

  // ---------- visitor events ----------

  function visitorReset(d) {
    state.adminRead = d.adminRead || 0;
    renderAll(d.messages);
    markReadSoon();
  }

  function visitorMsg(m) {
    upsertMessage(m);
    if (m.from === 'admin') markReadSoon();
  }

  // ---------- admin events ----------

  function adminReset(d) {
    state.convs = {};
    for (var i = 0; i < d.conversations.length; i++) state.convs[d.conversations[i].uid] = d.conversations[i];
    renderConvList();
    if (state.openConv) {
      if (state.convs[state.openConv]) openConversation(state.openConv, true);
      else closeConversation();
    }
  }

  function adminMsg(d) {
    state.convs[d.summary.uid] = d.summary;
    renderConvList();
    if (d.message.conv === state.openConv) {
      if (!state.openLoaded) state.openBuffer.push(d.message);
      else upsertMessage(d.message);
      renderTopbar();
      if (d.message.from === 'visitor') markReadSoon();
    }
  }

  function adminDelete(d) {
    if (d.summary) state.convs[d.conv] = d.summary;
    renderConvList();
    if (d.conv === state.openConv) removeMessage(d.id);
  }

  function adminReadEvent(d) {
    state.convs[d.conv] = d.summary;
    renderConvList();
    if (d.conv === state.openConv) updateTicks();
  }

  function adminConvDelete(d) {
    delete state.convs[d.conv];
    renderConvList();
    if (d.conv === state.openConv) closeConversation();
  }

  function adminPresence(d) {
    state.onlineVisitors = {};
    for (var i = 0; i < d.visitors.length; i++) state.onlineVisitors[d.visitors[i]] = true;
    renderConvList();
    renderTopbar();
  }

  // ---------- admin inbox ----------

  function convTime(ts) {
    var d = new Date(ts);
    var now = new Date();
    if (dayKey(ts) === dayKey(now.getTime())) return formatTime(ts);
    var y = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    if (dayKey(ts) === dayKey(y.getTime())) return 'دیروز';
    return fmtShortDate ? fmtShortDate.format(d) : d.toDateString();
  }

  // uid -> { sig, li }: lets the inbox redraw only the rows that changed.
  var convNodes = {};

  function buildConvItem(c, online, active, timeText) {
    var li = el('li');
    var btn = el('button', 'conv-item' + (active ? ' active' : '') + (c.unread ? ' unread' : ''));
    btn.type = 'button';
    btn.appendChild(setAvatar(el('span'), c.uid, c.name, online));
    var body = el('div', 'conv-body');
    var top = el('div', 'conv-top');
    var name = el('span', 'conv-name', c.name);
    name.dir = 'auto';
    name.title = c.name;
    top.appendChild(name);
    top.appendChild(el('time', 'conv-time', timeText));
    body.appendChild(top);
    var bottom = el('div', 'conv-bottom');
    var preview = el('span', 'conv-preview');
    if (c.last) {
      var text = c.last.text.replace(/\s+/g, ' ');
      if (c.last.from === 'admin') {
        preview.appendChild(el('b', '', 'شما: '));
        preview.appendChild(el('bdi', '', text));
      } else {
        preview.dir = 'auto'; // an English preview shows its start, a Persian one stays right-aligned
        preview.textContent = text;
      }
    } else {
      preview.textContent = 'پیامی نیست';
    }
    bottom.appendChild(preview);
    if (c.unread) bottom.appendChild(el('span', 'conv-unread', faCount(c.unread)));
    body.appendChild(bottom);
    btn.appendChild(body);
    btn.addEventListener('click', function () { openConversation(c.uid); });
    li.appendChild(btn);
    return li;
  }

  function renderConvList() {
    if (!isAdmin()) return;
    var ul = $('conv-list');
    var convs = Object.keys(state.convs).map(function (k) { return state.convs[k]; });
    convs.sort(function (a, b) { return b.lastTs - a.lastTs; });

    var total = 0;
    var order = [];
    var changed = [];
    var fresh = {};
    convs.forEach(function (c) {
      total += c.unread;
      order.push(c.uid);
      var online = !!state.onlineVisitors[c.uid];
      var active = c.uid === state.openConv;
      var timeText = convTime(c.lastTs);
      var sig = [c.name, timeText, c.unread, online, active, c.last ? c.last.from + ':' + c.last.text : ''].join('\u0001');
      var old = convNodes[c.uid];
      if (old && old.sig === sig) {
        fresh[c.uid] = old;
      } else {
        fresh[c.uid] = { sig: sig, li: buildConvItem(c, online, active, timeText) };
        changed.push({ old: old, entry: fresh[c.uid] });
      }
    });

    // Drop rows that were rebuilt or no longer exist, then move only the rows
    // that are out of place (a new message usually lifts a single row to the top).
    changed.forEach(function (ch) {
      if (ch.old && ch.old.li.parentNode === ul) ul.removeChild(ch.old.li);
    });
    Object.keys(convNodes).forEach(function (uid) {
      var li = convNodes[uid].li;
      if (!fresh[uid] && li.parentNode === ul) ul.removeChild(li);
    });
    var cursor = ul.firstChild;
    order.forEach(function (uid) {
      var li = fresh[uid].li;
      if (li === cursor) cursor = cursor.nextSibling;
      else ul.insertBefore(li, cursor);
    });
    while (cursor) {
      var next = cursor.nextSibling;
      ul.removeChild(cursor);
      cursor = next;
    }
    convNodes = fresh;

    $('inbox-empty').hidden = convs.length > 0;
    $('unread-total').hidden = !total;
    $('unread-total').textContent = faCount(total);
    updateTitle();
  }

  function openConversation(uid, keepScroll) {
    var switching = uid !== state.openConv;
    state.openConv = uid;
    state.openLoaded = false;
    state.openBuffer = [];
    app.classList.add('conv-open');
    if (switching) {
      list.innerHTML = '';
      $('empty').hidden = false;
      $('empty-text').textContent = 'در حال بارگذاری…';
      input.value = '';
      autosize();
      updateSendButton();
    }
    renderConvList();
    renderTopbar();
    api('GET', '/api/conversation?conv=' + encodeURIComponent(uid)).then(function (data) {
      if (state.openConv !== uid) return;
      state.convs[uid] = data.summary;
      renderAll(data.messages, keepScroll && !switching);
      state.openLoaded = true;
      var buffered = state.openBuffer;
      state.openBuffer = [];
      buffered.forEach(upsertMessage);
      renderConvList();
      renderTopbar();
      markReadSoon();
      if (!isTouch) input.focus();
    }, function (err) {
      if (state.openConv !== uid) return;
      if (err.status === 401) { handleUnauthorized(); return; }
      if (err.status === 404) { delete state.convs[uid]; closeConversation(); renderConvList(); return; }
      $('empty-text').textContent = errorText(err);
    });
  }

  function closeConversation() {
    state.openConv = null;
    state.openLoaded = false;
    app.classList.remove('conv-open');
    list.innerHTML = '';
    renderConvList();
  }

  $('back-btn').addEventListener('click', closeConversation);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isAdmin() && state.openConv && document.activeElement !== input) closeConversation();
  });

  $('conv-delete').addEventListener('click', function () {
    var c = state.convs[state.openConv];
    if (!c) return;
    if (!window.confirm('کل گفتگو با «' + c.name + '» برای همیشه حذف شود؟')) return;
    api('POST', '/api/conversation/delete', { conv: c.uid }).then(function () {
      delete state.convs[c.uid];
      closeConversation();
    }, function (err) {
      if (err.status === 401) handleUnauthorized(); else window.alert(errorText(err));
    });
  });

  // ---------- read receipts ----------

  var readTimer = null;
  function markReadSoon() {
    clearTimeout(readTimer);
    readTimer = setTimeout(markRead, 600);
  }
  function markRead() {
    if (document.hidden || !state.token) return;
    if (isAdmin()) {
      var c = state.convs[state.openConv];
      if (!c || !c.unread || !state.openLoaded) return;
      api('POST', '/api/read', { conv: c.uid }).catch(function () {});
    } else {
      state.unread = 0;
      updateTitle();
      if (state.lastReplyId <= state.readSent) return;
      state.readSent = state.lastReplyId;
      api('POST', '/api/read', {}).catch(function () { state.readSent = 0; });
    }
  }

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) markReadSoon();
  });

  // The other side has read up to this message id.
  function otherRead() {
    if (isAdmin()) {
      var c = state.convs[state.openConv];
      return c ? c.visitorRead : 0;
    }
    return state.adminRead;
  }

  function updateTicks() {
    var read = otherRead();
    var mine = list.querySelectorAll('li.msg.mine:not(.pending)');
    for (var i = 0; i < mine.length; i++) {
      var li = mine[i];
      var isRead = Number(li.getAttribute('data-id')) <= read;
      if (li.classList.contains('read') === isRead) continue;
      li.classList.toggle('read', isRead);
      var meta = li.querySelector('.msg-meta');
      meta.removeChild(meta.lastChild);
      meta.appendChild(tickIcon(isRead));
    }
  }

  function tickIcon(isRead) {
    var svg = icon(isRead ? 'i-check2' : 'i-check', isRead ? 'read' : '');
    var t = document.createElementNS(SVG_NS, 'title');
    t.textContent = isRead ? 'خوانده شد' : 'رسید';
    svg.appendChild(t);
    return svg;
  }

  // ---------- rendering messages ----------

  function isNearBottom() {
    return list.scrollHeight - list.scrollTop - list.clientHeight < 120;
  }
  function scrollToBottom() {
    list.scrollTop = list.scrollHeight;
    state.unseen = 0;
    renderJump();
  }
  function renderJump() {
    var show = !isNearBottom() && list.scrollHeight > list.clientHeight;
    $('jump').hidden = !show;
    $('jump-count').hidden = !state.unseen;
    $('jump-count').textContent = faCount(state.unseen);
  }
  $('jump').addEventListener('click', scrollToBottom);
  list.addEventListener('scroll', function () {
    if (isNearBottom()) state.unseen = 0;
    renderJump();
  });

  function formatTime(ts) {
    return fmtTime ? fmtTime.format(ts) : new Date(ts).toLocaleTimeString();
  }

  function dayKey(ts) {
    var d = new Date(ts);
    return d.getFullYear() + '-' + d.getMonth() + '-' + d.getDate();
  }
  function dayLabel(ts) {
    var d = new Date(ts);
    var today = new Date();
    var yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
    if (dayKey(ts) === dayKey(today.getTime())) return 'امروز';
    if (dayKey(ts) === dayKey(yesterday.getTime())) return 'دیروز';
    return fmtLongDate ? fmtLongDate.format(d) : d.toDateString();
  }

  var URL_RE = /(https?:\/\/[^\s<>"']+)/g;

  function fillText(node, text) {
    var parts = text.split(URL_RE);
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      if (i % 2 === 1) {
        var a = el('a', '', parts[i]);
        a.href = parts[i];
        a.target = '_blank';
        a.rel = 'noopener noreferrer nofollow';
        a.dir = 'ltr';
        node.appendChild(a);
      } else {
        node.appendChild(document.createTextNode(parts[i]));
      }
    }
  }

  // "Ours" = the side of the conversation the current user is on.
  function isOurs(m) { return isAdmin() ? m.from === 'admin' : m.from === 'visitor'; }

  function buildMessage(m, pending) {
    var ours = isOurs(m);
    var li = el('li', 'msg' + (ours ? ' mine' : '') + (pending ? ' pending' : ''));
    li.setAttribute('data-uid', m.uid);
    li.setAttribute('data-ts', m.ts);
    if (m.id) li.setAttribute('data-id', m.id);

    if (!ours) li.appendChild(setAvatar(el('span'), m.uid, m.name));

    var col = el('div', 'msg-col');
    var bubble = el('div', 'bubble ' + colorClass(m.uid));

    // Visitors see which admin answered; admins see which colleague wrote.
    var showName = isAdmin() ? (ours && m.uid !== state.user.uid) : !ours;
    if (showName) {
      var name = el('div', 'msg-name');
      var nameText = el('span', '', m.name);
      nameText.dir = 'auto';
      nameText.title = m.name;
      name.appendChild(nameText);
      if (m.from === 'admin' && !isAdmin()) name.appendChild(el('span', 'badge', 'مدیر'));
      bubble.appendChild(name);
    }

    var text = el('div', 'msg-text');
    text.dir = 'auto';
    fillText(text, m.text);
    bubble.appendChild(text);

    var meta = el('span', 'msg-meta');
    var time = el('time', '', formatTime(m.ts));
    time.dateTime = new Date(m.ts).toISOString();
    meta.appendChild(time);
    if (ours) {
      var isRead = !pending && m.id <= otherRead();
      if (isRead) li.classList.add('read');
      meta.appendChild(pending ? icon('i-clock') : tickIcon(isRead));
    }
    bubble.appendChild(meta);
    col.appendChild(bubble);

    var actions = null;
    if (!pending && m.id && (isAdmin() || ours)) {
      actions = el('div', 'msg-actions');
      var del = el('button');
      del.type = 'button';
      del.title = 'حذف پیام';
      del.setAttribute('aria-label', 'حذف پیام');
      del.appendChild(icon('i-trash'));
      del.addEventListener('click', function (e) {
        e.stopPropagation();
        deleteMessage(m);
      });
      actions.appendChild(del);
      // Phones have no hover: tap the bubble to show the delete button.
      bubble.addEventListener('click', function (e) {
        if (e.target.closest('a')) return;
        var open = li.classList.contains('show-actions');
        hideActions();
        if (!open) li.classList.add('show-actions');
      });
    }

    // Row order (RTL): theirs = avatar, bubble, actions; ours = actions, bubble.
    if (ours && actions) li.appendChild(actions);
    li.appendChild(col);
    if (!ours && actions) li.appendChild(actions);
    return li;
  }

  function hideActions() {
    var shown = list.querySelectorAll('.show-actions');
    for (var i = 0; i < shown.length; i++) shown[i].classList.remove('show-actions');
  }
  document.addEventListener('click', function (e) {
    if (!(e.target.closest && e.target.closest('.msg'))) hideActions();
  });

  // Groups consecutive messages, adds day separators and the empty state.
  function relayout() {
    var seps = list.querySelectorAll('li.day');
    for (var s = 0; s < seps.length; s++) list.removeChild(seps[s]);

    var msgs = list.querySelectorAll('li.msg');
    var prev = null;
    for (var i = 0; i < msgs.length; i++) {
      var li = msgs[i];
      var ts = Number(li.getAttribute('data-ts'));
      var newDay = !prev || dayKey(Number(prev.getAttribute('data-ts'))) !== dayKey(ts);
      if (newDay) {
        var sep = el('li', 'day');
        sep.appendChild(el('span', '', dayLabel(ts)));
        list.insertBefore(sep, li);
      }
      var newGroup = newDay || prev.getAttribute('data-uid') !== li.getAttribute('data-uid') ||
        ts - Number(prev.getAttribute('data-ts')) > 5 * 60 * 1000;
      li.classList.toggle('first', newGroup);
      if (prev) prev.classList.toggle('last', newGroup);
      prev = li;
    }
    if (prev) prev.classList.add('last');

    $('empty').hidden = msgs.length > 0;
    $('empty-text').textContent = isAdmin()
      ? 'پیامی در این گفتگو نیست.'
      : 'پیام خود را بنویسید. فقط ما آن را می‌بینیم و در اولین فرصت جواب می‌دهیم.';
  }

  // Inserts a confirmed message in id order, above any still-pending ones.
  function insertConfirmed(li, id) {
    var ref = list.lastElementChild;
    while (ref && (ref.classList.contains('pending') || ref.classList.contains('day') ||
      Number(ref.getAttribute('data-id')) > id)) {
      ref = ref.previousElementSibling;
    }
    list.insertBefore(li, ref ? ref.nextSibling : list.firstChild);
  }

  function upsertMessage(m) {
    if (isAdmin() && m.conv !== state.openConv) return;
    if (m.cid && state.pending[m.cid] && isOurs(m) && m.uid === state.user.uid) dropPending(m.cid, true);
    if (!isOurs(m) && m.id > state.lastReplyId) state.lastReplyId = m.id;
    if (list.querySelector('li[data-id="' + Number(m.id) + '"]')) { relayout(); return; }
    var stick = isNearBottom();
    var li = buildMessage(m, false);
    if (m.uid !== state.user.uid) li.classList.add('enter');
    insertConfirmed(li, m.id);
    relayout();
    var ours = isOurs(m);
    if (stick || (ours && m.uid === state.user.uid)) {
      scrollToBottom();
    } else {
      state.unseen += 1;
      renderJump();
    }
    if (!ours && document.hidden && !isAdmin()) {
      state.unread += 1;
      updateTitle();
    }
  }

  function renderAll(messages, keepScroll) {
    // Messages delivered while we were disconnected are no longer pending.
    for (var k = 0; k < messages.length; k++) {
      var m = messages[k];
      if (m.cid && state.pending[m.cid] && m.uid === state.user.uid) dropPending(m.cid, true);
      if (!isOurs(m) && m.id > state.lastReplyId) state.lastReplyId = m.id;
    }
    var scroll = list.scrollTop;
    list.innerHTML = '';
    var frag = document.createDocumentFragment();
    for (var i = 0; i < messages.length; i++) frag.appendChild(buildMessage(messages[i], false));
    var conv = isAdmin() ? state.openConv : null;
    Object.keys(state.pending).forEach(function (cid) {
      var p = state.pending[cid];
      if (p.conv === conv) frag.appendChild(p.li);
    });
    list.appendChild(frag);
    relayout();
    if (keepScroll) list.scrollTop = scroll; else scrollToBottom();
  }

  function removeMessage(id) {
    var li = list.querySelector('li[data-id="' + Number(id) + '"]');
    if (li) {
      li.parentNode.removeChild(li);
      relayout();
      renderJump();
    }
  }

  // Day labels ("today", "yesterday") change at midnight.
  setInterval(function () {
    if (state.user && list.firstChild) relayout();
    if (isAdmin()) renderConvList();
  }, 10 * 60 * 1000);

  // ---------- sending ----------

  function autosize() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight + 3, 160) + 'px';
  }
  function updateSendButton() {
    sendBtn.disabled = !input.value.trim();
  }
  input.addEventListener('input', function () {
    autosize();
    updateSendButton();
  });

  input.addEventListener('keydown', function (e) {
    // On computers Enter sends and Shift+Enter adds a new line.
    // On phones Enter adds a new line and the button sends.
    if (e.key === 'Enter' && !e.shiftKey && !isTouch && !e.isComposing) {
      e.preventDefault();
      submit();
    }
  });

  // Keep the keyboard open on phones when tapping the send button.
  sendBtn.addEventListener('mousedown', function (e) { e.preventDefault(); });

  $('composer').addEventListener('submit', function (e) {
    e.preventDefault();
    submit();
  });

  function submit() {
    var text = input.value.trim();
    if (!text || !state.user) return;
    if (isAdmin() && !state.openConv) return;
    if (text.length > state.config.maxMessageLength) { window.alert(ERRORS.too_long); return; }
    input.value = '';
    autosize();
    updateSendButton();

    var cid = randomId();
    var conv = isAdmin() ? state.openConv : null;
    var li = buildMessage({
      uid: state.user.uid, name: state.user.name, from: isAdmin() ? 'admin' : 'visitor', text: text, ts: Date.now()
    }, true);
    li.setAttribute('data-cid', cid);
    list.appendChild(li);
    relayout();
    scrollToBottom();
    state.pending[cid] = { text: text, conv: conv, li: li, tries: 0, timer: null };
    trySend(cid);
  }

  function setPendingError(p, text, actions) {
    var col = p.li.querySelector('.msg-col');
    var old = col.querySelector('.msg-error');
    if (old) col.removeChild(old);
    var meta = p.li.querySelector('.msg-meta');
    meta.removeChild(meta.lastChild);
    p.li.classList.toggle('failed', !!text);
    meta.appendChild(icon(text ? 'i-alert' : 'i-clock'));
    if (!text) return;
    var stick = isNearBottom();
    var box = el('div', 'msg-error');
    box.appendChild(el('span', '', text));
    actions.forEach(function (a) {
      var b = el('button');
      b.type = 'button';
      if (a.icon) b.appendChild(icon(a.icon));
      b.appendChild(document.createTextNode(a.label));
      b.addEventListener('click', a.run);
      box.appendChild(b);
    });
    col.appendChild(box);
    if (stick) scrollToBottom();
  }

  function dropPending(cid, delivered) {
    var p = state.pending[cid];
    if (!p) return;
    clearTimeout(p.timer);
    if (p.li.parentNode) p.li.parentNode.removeChild(p.li);
    delete state.pending[cid];
    if (!delivered) relayout();
  }

  function trySend(cid) {
    var p = state.pending[cid];
    if (!p) return;
    clearTimeout(p.timer);
    setPendingError(p, '');
    var body = { text: p.text, cid: cid };
    if (p.conv) body.conv = p.conv;
    api('POST', '/api/send', body, 20000).then(function (data) {
      if (state.pending[cid]) dropPending(cid, true);
      upsertMessage(data.message);
    }, function (err) {
      if (!state.pending[cid]) return;
      if (err.status === 401) { handleUnauthorized(); return; }
      var retryable = !err.status || err.status === 429 || err.status >= 500;
      if (retryable) {
        // Keep retrying in the background; poor connections recover eventually.
        p.tries += 1;
        var delay = Math.min(30000, 2000 * Math.pow(2, p.tries - 1));
        setPendingError(p, 'ارسال نشد؛ تلاش خودکار…', [
          { label: 'الان بفرست', icon: 'i-retry', run: function () { trySend(cid); } },
          { label: 'لغو', run: function () { dropPending(cid); } }
        ]);
        p.timer = setTimeout(function () { trySend(cid); }, delay);
      } else {
        setPendingError(p, errorText(err), [
          { label: 'حذف', run: function () { dropPending(cid); } }
        ]);
      }
    });
  }

  function deleteMessage(m) {
    if (!window.confirm('این پیام حذف شود؟ برای طرف مقابل هم حذف می‌شود.')) return;
    api('POST', '/api/delete', { id: m.id, conv: m.conv }).then(function () {
      removeMessage(m.id);
    }, function (err) {
      if (err.status === 401) handleUnauthorized();
      else if (err.code === 'not_found') removeMessage(m.id);
      else window.alert(errorText(err));
    });
  }

  // ---------- start ----------

  function loadConfig(attempt) {
    return api('GET', '/api/config').then(function (cfg) {
      state.config = cfg;
      if (cfg.title) {
        state.baseTitle = cfg.title;
        document.title = cfg.title;
      }
      if (cfg.maxMessageLength) input.maxLength = cfg.maxMessageLength;
    }, function () {
      if (attempt < 5) {
        return new Promise(function (r) { setTimeout(r, 1500 * (attempt + 1)); })
          .then(function () { return loadConfig(attempt + 1); });
      }
      return undefined;
    });
  }

  loadConfig(0).then(function () {
    if (state.token && state.user) startApp();
    else showJoin();
  });
})();
