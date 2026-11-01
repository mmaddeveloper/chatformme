(function () {
  'use strict';

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

  function faNum(n) {
    try { return Number(n).toLocaleString('fa-IR'); } catch (e) { return String(n); }
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function icon(id) {
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    var use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', '#' + id);
    svg.appendChild(use);
    return svg;
  }

  // Stable color (0-7) and initial for each person.
  function colorClass(uid) {
    var h = 0;
    for (var i = 0; i < uid.length; i++) h = (h * 31 + uid.charCodeAt(i)) >>> 0;
    return 'c' + (h % 8);
  }
  function initial(name) {
    var chars = Array.from(String(name).trim());
    return chars.length ? chars[0].toUpperCase() : '?';
  }
  function makeAvatar(user) {
    var a = el('span', 'avatar ' + colorClass(user.uid || ''), initial(user.name || ''));
    a.setAttribute('aria-hidden', 'true');
    return a;
  }

  var ERRORS = {
    bad_password: 'رمز اشتباه است.',
    bad_name: 'نام باید بین ۱ تا ۳۲ حرف باشد.',
    rate_limited: 'درخواست‌ها زیاد است؛ چند لحظه صبر کنید.',
    too_long: 'پیام خیلی طولانی است.',
    empty: 'پیام خالی است.',
    forbidden: 'اجازهٔ این کار را ندارید.',
    not_found: 'پیام پیدا نشد (شاید قبلاً حذف شده).',
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
    online: [],
    lastSeq: 0,
    lastEventAt: 0,
    reconnectTimer: null,
    reconnectDelay: 2000,
    pending: {},      // cid -> { text, li, tries, timer }
    unread: 0,        // for the tab title
    unseen: 0,        // for the "new messages" button
    baseTitle: document.title
  };

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
    closeDrawer();
    $('chat').hidden = true;
    $('join').hidden = false;
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
      startChat();
    }, function (err) {
      state.token = oldToken;
      showJoinError(errorText(err));
    }).then(function () { btn.disabled = false; });
  });

  // ---------- chat screen ----------

  var list = $('messages');
  var input = $('input');
  var sendBtn = $('send-btn');

  function startChat() {
    $('join').hidden = true;
    $('chat').hidden = false;
    list.innerHTML = '';
    state.lastSeq = 0;
    renderMe();
    relayout();
    connect();
    updateSendButton();
    if (!isTouch) input.focus();
  }

  function renderMe() {
    var me = state.user;
    var av = $('me-avatar');
    av.className = 'avatar ' + colorClass(me.uid);
    av.textContent = initial(me.name);
    $('me-name').textContent = me.name;
    $('me-role').textContent = me.admin ? 'مدیر گفتگو' : 'شما';
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
    showJoin();
  }

  $('logout-btn').addEventListener('click', function () {
    if (window.confirm('از گفتگو خارج می‌شوید؟')) logout();
  });

  function handleUnauthorized() {
    logout();
    showJoinError('نشست شما منقضی شده یا رمز تغییر کرده؛ لطفاً دوباره وارد شوید.');
  }

  // ---------- people drawer (phones) ----------

  var app = $('chat');
  function openDrawer() {
    app.classList.add('drawer-open');
    $('online-btn').setAttribute('aria-expanded', 'true');
    $('side-close').focus();
  }
  function closeDrawer() {
    if (!app.classList.contains('drawer-open')) return;
    app.classList.remove('drawer-open');
    $('online-btn').setAttribute('aria-expanded', 'false');
  }
  $('online-btn').addEventListener('click', openDrawer);
  $('side-close').addEventListener('click', closeDrawer);
  $('backdrop').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeDrawer();
  });

  // ---------- connection (Server-Sent Events) ----------

  function setStatus(s) {
    state.connState = s;
    renderStatus();
  }

  function renderStatus() {
    var s = state.connState;
    $('status').setAttribute('data-state', s);
    var text;
    if (s === 'online') text = faNum(state.online.length) + ' نفر آنلاین';
    else if (s === 'offline') text = 'اتصال قطع است؛ تلاش دوباره…';
    else text = 'در حال اتصال…';
    $('status-text').textContent = text;
  }

  function closeStream() {
    if (state.es) { state.es.close(); state.es = null; }
    if (state.reconnectTimer) { clearTimeout(state.reconnectTimer); state.reconnectTimer = null; }
  }

  function connect() {
    closeStream();
    if (!state.token) return;
    setStatus('connecting');
    var url = '/api/stream?token=' + encodeURIComponent(state.token) + '&since=' + state.lastSeq;
    var es = new EventSource(url);
    state.es = es;
    state.lastEventAt = Date.now();

    function seen(e) {
      state.lastEventAt = Date.now();
      if (e.lastEventId) {
        var n = parseInt(e.lastEventId, 10);
        if (n > state.lastSeq) state.lastSeq = n;
      }
    }

    es.onopen = function () {
      state.reconnectDelay = 2000;
      state.lastEventAt = Date.now();
      setStatus('online');
    };
    es.addEventListener('reset', function (e) {
      state.lastEventAt = Date.now();
      state.lastSeq = parseInt(e.lastEventId, 10) || 0;
      renderAll(JSON.parse(e.data).messages);
    });
    es.addEventListener('msg', function (e) { seen(e); upsertMessage(JSON.parse(e.data)); });
    es.addEventListener('delete', function (e) { seen(e); removeMessage(JSON.parse(e.data).id); });
    es.addEventListener('presence', function (e) { seen(e); renderPresence(JSON.parse(e.data)); });
    es.addEventListener('ping', seen);
    es.onerror = function () {
      if (es !== state.es) return;
      if (es.readyState === 2 /* CLOSED */) {
        // The browser gave up (bad token, server full, ...). Find out why.
        setStatus('offline');
        api('GET', '/api/me').then(scheduleReconnect, function (err) {
          if (err.status === 401) handleUnauthorized(); else scheduleReconnect();
        });
      } else {
        setStatus('connecting'); // the browser reconnects by itself
      }
    };
  }

  function scheduleReconnect() {
    if (!state.token || state.reconnectTimer) return;
    if (state.es) { state.es.close(); state.es = null; }
    setStatus('offline');
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

  // ---------- rendering ----------

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
    $('jump-count').textContent = faNum(state.unseen);
  }
  $('jump').addEventListener('click', scrollToBottom);
  list.addEventListener('scroll', function () {
    if (isNearBottom()) state.unseen = 0;
    renderJump();
  });

  function formatTime(ts) {
    var d = new Date(ts);
    try { return d.toLocaleTimeString('fa-IR', { hour: '2-digit', minute: '2-digit' }); } catch (e) { return d.toLocaleTimeString(); }
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
    try {
      return d.toLocaleDateString('fa-IR', { weekday: 'long', day: 'numeric', month: 'long' });
    } catch (e) {
      return d.toDateString();
    }
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

  function isMine(m) { return !!(state.user && m.uid === state.user.uid); }

  function buildMessage(m, pending) {
    var mine = isMine(m);
    var li = el('li', 'msg' + (mine ? ' mine' : '') + (m.admin ? ' admin' : '') + (pending ? ' pending' : ''));
    li.setAttribute('data-uid', m.uid);
    li.setAttribute('data-ts', m.ts);
    if (m.id) li.setAttribute('data-id', m.id);

    if (!mine) li.appendChild(makeAvatar(m));

    var col = el('div', 'msg-col');
    var bubble = el('div', 'bubble ' + colorClass(m.uid));

    if (!mine) {
      var name = el('div', 'msg-name');
      var nameText = el('span', '', m.name);
      nameText.dir = 'auto';
      name.appendChild(nameText);
      if (m.admin) name.appendChild(el('span', 'badge', 'مدیر'));
      bubble.appendChild(name);
    }

    var text = el('div', 'msg-text');
    text.dir = 'auto';
    fillText(text, m.text);
    bubble.appendChild(text);

    var meta = el('span', 'msg-meta');
    var time = el('time', '', formatTime(m.ts));
    time.dateTime = new Date(m.ts).toISOString();
    time.title = new Date(m.ts).toLocaleString('fa-IR');
    meta.appendChild(time);
    if (mine) meta.appendChild(icon(pending ? 'i-clock' : 'i-check'));
    bubble.appendChild(meta);

    col.appendChild(bubble);

    var canDelete = !pending && m.id && (mine || (state.user && state.user.admin));
    var actions = null;
    if (canDelete) {
      actions = el('div', 'msg-actions');
      var del = el('button');
      del.type = 'button';
      del.title = 'حذف پیام';
      del.setAttribute('aria-label', 'حذف پیام');
      del.appendChild(icon('i-trash'));
      del.addEventListener('click', function (e) {
        e.stopPropagation();
        deleteMessage(m.id);
      });
      actions.appendChild(del);
      // Phones have no hover: tap the bubble to show the delete button.
      bubble.addEventListener('click', function (e) {
        if (e.target.closest('a')) return;
        var open = li.classList.contains('show-actions');
        var shown = list.querySelectorAll('.show-actions');
        for (var i = 0; i < shown.length; i++) shown[i].classList.remove('show-actions');
        if (!open) li.classList.add('show-actions');
      });
    }

    // Order inside the row (RTL): others = avatar, bubble, actions;
    // mine = actions, bubble (so the button sits toward the middle).
    if (mine && actions) li.appendChild(actions);
    li.appendChild(col);
    if (!mine && actions) li.appendChild(actions);
    return li;
  }

  // Groups consecutive messages, adds day separators and the empty state.
  function relayout() {
    var seps = list.querySelectorAll('li.day');
    for (var s = 0; s < seps.length; s++) list.removeChild(seps[s]);

    var msgs = list.querySelectorAll('li.msg');
    var prev = null;
    for (var i = 0; i < msgs.length; i++) {
      var li = msgs[i];
      var ts = Number(li.getAttribute('data-ts'));
      var uid = li.getAttribute('data-uid');
      var newDay = !prev || dayKey(Number(prev.getAttribute('data-ts'))) !== dayKey(ts);
      if (newDay) {
        var sep = el('li', 'day');
        sep.appendChild(el('span', '', dayLabel(ts)));
        list.insertBefore(sep, li);
      }
      var newGroup = newDay || !prev || prev.getAttribute('data-uid') !== uid ||
        ts - Number(prev.getAttribute('data-ts')) > 5 * 60 * 1000;
      li.classList.toggle('first', newGroup);
      if (prev) prev.classList.toggle('last', newGroup);
      prev = li;
    }
    if (prev) prev.classList.add('last');
    $('empty').hidden = msgs.length > 0;
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
    if (m.cid && state.pending[m.cid] && isMine(m)) dropPending(m.cid, true);
    if (list.querySelector('li[data-id="' + Number(m.id) + '"]')) { relayout(); return; }
    var stick = isNearBottom();
    insertConfirmed(buildMessage(m, false), m.id);
    relayout();
    var mine = isMine(m);
    if (stick || mine) {
      scrollToBottom();
    } else {
      state.unseen += 1;
      renderJump();
    }
    if (!mine && document.hidden) {
      state.unread += 1;
      document.title = '(' + faNum(state.unread) + ') ' + state.baseTitle;
    }
  }

  function renderAll(messages) {
    // Messages delivered while we were disconnected are no longer pending.
    for (var k = 0; k < messages.length; k++) {
      var m = messages[k];
      if (m.cid && state.pending[m.cid] && isMine(m)) dropPending(m.cid, true);
    }
    var pendingEls = list.querySelectorAll('li.pending');
    list.innerHTML = '';
    var frag = document.createDocumentFragment();
    for (var i = 0; i < messages.length; i++) frag.appendChild(buildMessage(messages[i], false));
    for (var j = 0; j < pendingEls.length; j++) frag.appendChild(pendingEls[j]);
    list.appendChild(frag);
    relayout();
    scrollToBottom();
  }

  function removeMessage(id) {
    var li = list.querySelector('li[data-id="' + Number(id) + '"]');
    if (li) {
      li.parentNode.removeChild(li);
      relayout();
      renderJump();
    }
  }

  function renderPresence(users) {
    state.online = users;
    var me = state.user ? state.user.uid : '';
    users.sort(function (a, b) {
      if ((a.uid === me) !== (b.uid === me)) return a.uid === me ? -1 : 1;
      if (a.admin !== b.admin) return a.admin ? -1 : 1;
      return a.name.localeCompare(b.name, 'fa');
    });
    $('online-count').textContent = faNum(users.length);
    $('side-count').textContent = faNum(users.length);
    var ul = $('online-list');
    ul.innerHTML = '';
    for (var i = 0; i < users.length; i++) {
      var u = users[i];
      var li = el('li');
      li.appendChild(makeAvatar(u));
      var name = el('span', 'person-name', u.name);
      name.dir = 'auto';
      li.appendChild(name);
      if (u.uid === me) li.appendChild(el('span', 'person-you', 'شما'));
      if (u.admin) li.appendChild(el('span', 'badge', 'مدیر'));
      ul.appendChild(li);
    }
    renderStatus();
  }

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) {
      state.unread = 0;
      document.title = state.baseTitle;
    }
  });

  // Tapping elsewhere hides the delete button again (phones).
  document.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('.msg')) return;
    var shown = list.querySelectorAll('.show-actions');
    for (var i = 0; i < shown.length; i++) shown[i].classList.remove('show-actions');
  });

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
    if (text.length > state.config.maxMessageLength) { window.alert(ERRORS.too_long); return; }
    input.value = '';
    autosize();
    updateSendButton();

    var cid = randomId();
    var li = buildMessage({ uid: state.user.uid, name: state.user.name, admin: state.user.admin, text: text, ts: Date.now() }, true);
    li.setAttribute('data-cid', cid);
    list.appendChild(li);
    relayout();
    scrollToBottom();
    state.pending[cid] = { text: text, li: li, tries: 0, timer: null };
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
    api('POST', '/api/send', { text: p.text, cid: cid }, 20000).then(function (data) {
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

  function deleteMessage(id) {
    if (!window.confirm('این پیام برای همه حذف شود؟')) return;
    api('POST', '/api/delete', { id: id }).then(function () {
      removeMessage(id);
    }, function (err) {
      if (err.status === 401) handleUnauthorized();
      else if (err.code === 'not_found') removeMessage(id);
      else window.alert(errorText(err));
    });
  }

  // Day labels ("today", "yesterday") change at midnight.
  setInterval(function () { if (state.user) relayout(); }, 10 * 60 * 1000);

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
    if (state.token && state.user) startChat();
    else showJoin();
  });
})();
