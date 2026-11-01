(function () {
  'use strict';

  // ---------- small helpers ----------

  var $ = function (id) { return document.getElementById(id); };

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

  var ERRORS = {
    bad_password: 'رمز اشتباه است.',
    bad_name: 'نام باید بین ۱ تا ۳۲ حرف باشد.',
    rate_limited: 'درخواست‌ها زیاد است؛ چند لحظه صبر کنید.',
    too_long: 'پیام خیلی طولانی است.',
    empty: 'پیام خالی است.',
    forbidden: 'اجازهٔ این کار را ندارید.',
    not_found: 'پیام پیدا نشد (شاید قبلاً حذف شده).',
    network: 'ارتباط با سرور برقرار نشد. اتصال اینترنت را بررسی کنید.',
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
    lastSeq: 0,
    lastEventAt: 0,
    reconnectTimer: null,
    reconnectDelay: 2000,
    pending: {},      // cid -> { text, li, tries, timer }
    unread: 0,
    baseTitle: document.title
  };

  var isTouch = window.matchMedia && window.matchMedia('(pointer: coarse)').matches;

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
    }, function (e) {
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
    var lastName = storage.get('chat.name');
    if (lastName && !$('name').value) $('name').value = lastName;
    $('password-row').hidden = !state.config.passwordRequired;
    $('admin-toggle').hidden = state.config.passwordRequired || !state.config.adminEnabled;
    showJoinError(message || '');
    setTimeout(function () { $('name').focus(); }, 0);
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

  function startChat() {
    $('join').hidden = true;
    $('chat').hidden = false;
    list.innerHTML = '';
    state.lastSeq = 0;
    connect();
    if (!isTouch) input.focus();
  }

  function logout() {
    closeStream();
    var pendingIds = Object.keys(state.pending);
    for (var i = 0; i < pendingIds.length; i++) clearTimeout(state.pending[pendingIds[i]].timer);
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

  // ---------- connection (Server-Sent Events) ----------

  function setStatus(s) {
    var el = $('status');
    el.setAttribute('data-state', s);
    $('status-text').textContent = s === 'online' ? 'متصل' : s === 'offline' ? 'قطع — تلاش دوباره…' : 'در حال اتصال…';
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
    return list.scrollHeight - list.scrollTop - list.clientHeight < 80;
  }
  function scrollToBottom() {
    list.scrollTop = list.scrollHeight;
    $('jump').hidden = true;
  }
  $('jump').addEventListener('click', scrollToBottom);
  list.addEventListener('scroll', function () { if (isNearBottom()) $('jump').hidden = true; });

  function formatTime(ts) {
    var d = new Date(ts);
    var now = new Date();
    var opts = { hour: '2-digit', minute: '2-digit' };
    if (d.toDateString() !== now.toDateString()) { opts.month = 'short'; opts.day = 'numeric'; }
    try { return d.toLocaleString('fa-IR', opts); } catch (e) { return d.toLocaleString(); }
  }

  var URL_RE = /(https?:\/\/[^\s<>"']+)/g;

  function fillText(el, text) {
    var parts = text.split(URL_RE);
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      if (i % 2 === 1) {
        var a = document.createElement('a');
        a.href = parts[i];
        a.textContent = parts[i];
        a.target = '_blank';
        a.rel = 'noopener noreferrer nofollow';
        a.dir = 'ltr';
        el.appendChild(a);
      } else {
        el.appendChild(document.createTextNode(parts[i]));
      }
    }
  }

  function buildMessage(m, opts) {
    var mine = state.user && m.uid === state.user.uid;
    var li = document.createElement('li');
    li.className = 'msg' + (mine ? ' mine' : '') + (m.admin ? ' admin' : '');
    if (m.id) li.setAttribute('data-id', m.id);

    if (!mine) {
      var name = document.createElement('div');
      name.className = 'msg-name';
      var nameText = document.createElement('span');
      nameText.textContent = m.name;
      nameText.dir = 'auto';
      name.appendChild(nameText);
      if (m.admin) {
        var badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = 'مدیر';
        name.appendChild(badge);
      }
      li.appendChild(name);
    }

    var text = document.createElement('div');
    text.className = 'msg-text';
    text.dir = 'auto';
    fillText(text, m.text);
    li.appendChild(text);

    var meta = document.createElement('div');
    meta.className = 'msg-meta';
    li.appendChild(meta);

    if (opts && opts.pending) {
      li.classList.add('pending');
      var st = document.createElement('span');
      st.className = 'msg-status';
      st.textContent = 'در حال ارسال…';
      meta.appendChild(st);
    } else {
      if (mine || (state.user && state.user.admin)) {
        var del = document.createElement('button');
        del.type = 'button';
        del.textContent = 'حذف';
        del.addEventListener('click', function () { deleteMessage(m.id); });
        meta.appendChild(del);
      }
      var time = document.createElement('time');
      time.textContent = formatTime(m.ts);
      time.dateTime = new Date(m.ts).toISOString();
      meta.appendChild(time);
    }
    return li;
  }

  // Inserts a confirmed message in id order, above any still-pending ones.
  function insertConfirmed(li, id) {
    var ref = list.lastElementChild;
    while (ref && (ref.classList.contains('pending') || Number(ref.getAttribute('data-id')) > id)) {
      ref = ref.previousElementSibling;
    }
    list.insertBefore(li, ref ? ref.nextSibling : list.firstChild);
  }

  function upsertMessage(m) {
    if (m.cid && state.pending[m.cid] && state.user && m.uid === state.user.uid) {
      var p = state.pending[m.cid];
      clearTimeout(p.timer);
      if (p.li.parentNode) p.li.parentNode.removeChild(p.li);
      delete state.pending[m.cid];
    }
    if (list.querySelector('li[data-id="' + m.id + '"]')) return;
    var stick = isNearBottom();
    insertConfirmed(buildMessage(m), m.id);
    var mine = state.user && m.uid === state.user.uid;
    if (stick || mine) scrollToBottom(); else $('jump').hidden = false;
    if (!mine && document.hidden) {
      state.unread += 1;
      document.title = '(' + faNum(state.unread) + ') ' + state.baseTitle;
    }
  }

  function renderAll(messages) {
    // Messages that were delivered while we were disconnected are no longer pending.
    for (var k = 0; k < messages.length; k++) {
      var m = messages[k];
      if (m.cid && state.pending[m.cid] && state.user && m.uid === state.user.uid) dropPending(m.cid);
    }
    var pendingEls = list.querySelectorAll('li.pending');
    list.innerHTML = '';
    var frag = document.createDocumentFragment();
    for (var i = 0; i < messages.length; i++) frag.appendChild(buildMessage(messages[i]));
    for (var j = 0; j < pendingEls.length; j++) frag.appendChild(pendingEls[j]);
    list.appendChild(frag);
    scrollToBottom();
  }

  function removeMessage(id) {
    var li = list.querySelector('li[data-id="' + Number(id) + '"]');
    if (li) li.parentNode.removeChild(li);
  }

  function renderPresence(users) {
    $('online-count').textContent = faNum(users.length);
    var ul = $('online-list');
    ul.innerHTML = '';
    users.sort(function (a, b) { return (b.admin ? 1 : 0) - (a.admin ? 1 : 0); });
    for (var i = 0; i < users.length; i++) {
      var li = document.createElement('li');
      li.dir = 'auto';
      li.textContent = users[i].name + (users[i].admin ? ' (مدیر)' : '');
      ul.appendChild(li);
    }
  }

  $('online-btn').addEventListener('click', function () {
    var panel = $('online-panel');
    panel.hidden = !panel.hidden;
    $('online-btn').setAttribute('aria-expanded', String(!panel.hidden));
  });

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) {
      state.unread = 0;
      document.title = state.baseTitle;
    }
  });

  // ---------- sending ----------

  function autosize() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight + 2, 160) + 'px';
  }
  input.addEventListener('input', autosize);

  input.addEventListener('keydown', function (e) {
    // On computers Enter sends and Shift+Enter adds a new line.
    // On phones Enter adds a new line and the button sends.
    if (e.key === 'Enter' && !e.shiftKey && !isTouch && !e.isComposing) {
      e.preventDefault();
      submit();
    }
  });

  $('composer').addEventListener('submit', function (e) {
    e.preventDefault();
    submit();
  });

  function submit() {
    var text = input.value.trim();
    if (!text) return;
    if (text.length > state.config.maxMessageLength) { window.alert(ERRORS.too_long); return; }
    input.value = '';
    autosize();
    if (!isTouch) input.focus();

    var cid = randomId();
    var li = buildMessage({ uid: state.user.uid, name: state.user.name, admin: state.user.admin, text: text }, { pending: true });
    li.setAttribute('data-cid', cid);
    list.appendChild(li);
    scrollToBottom();
    state.pending[cid] = { text: text, li: li, tries: 0, timer: null };
    trySend(cid);
  }

  function setPendingStatus(p, text, failed, actions) {
    var meta = p.li.querySelector('.msg-meta');
    meta.innerHTML = '';
    p.li.classList.toggle('failed', !!failed);
    var st = document.createElement('span');
    st.textContent = text;
    meta.appendChild(st);
    (actions || []).forEach(function (a) {
      var b = document.createElement('button');
      b.type = 'button';
      b.textContent = a.label;
      b.addEventListener('click', a.run);
      meta.appendChild(b);
    });
  }

  function dropPending(cid) {
    var p = state.pending[cid];
    if (!p) return;
    clearTimeout(p.timer);
    if (p.li.parentNode) p.li.parentNode.removeChild(p.li);
    delete state.pending[cid];
  }

  function trySend(cid) {
    var p = state.pending[cid];
    if (!p) return;
    clearTimeout(p.timer);
    setPendingStatus(p, 'در حال ارسال…', false);
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
        setPendingStatus(p, 'ارسال نشد؛ دوباره تلاش می‌شود…', true, [
          { label: 'الان بفرست', run: function () { trySend(cid); } },
          { label: 'لغو', run: function () { dropPending(cid); } }
        ]);
        p.timer = setTimeout(function () { trySend(cid); }, delay);
      } else {
        setPendingStatus(p, errorText(err), true, [
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
