/* vault42 ROOT OF TRUST — vanilla JS
   Live trust chain loop + reduced-motion static final state.
   Append-only hash-chained audit simulation (real SHA-256 when available).
   Copy buttons, tabs, full keyboard, prefers-reduced-motion guards.
   No frameworks. All symbols declared before use. */

(function () {
  'use strict';

  // ---------- constants / samples ----------
  const SAMPLE_JWT = {
    header: { alg: 'RS256', typ: 'JWT', kid: 'a1b2c3d4' },
    payload: {
      iss: 'https://vault.42-v.com',
      aud: 'https://vault.42-v.com',
      sub: 'u_9f3c2a1b',
      exp: 1750996800,
      iat: 1750995900,
      jti: 't_e7f2a9',
      roles: ['user'],
      fingerprint: '3f2a1c...9e',
      client_id: 'web'
    },
    signature: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
  };

  const AUDIT_SEED = [
    { ts: '2026-06-27T11:04:12Z', event: 'login_success', ip: '203.0.113.41' },
    { ts: '2026-06-27T11:04:18Z', event: 'token_refresh', ip: '203.0.113.41' },
    { ts: '2026-06-27T11:07:51Z', event: '2fa_verify', ip: '198.51.100.7' },
    { ts: '2026-06-27T11:12:03Z', event: 'session_revoke', ip: '203.0.113.41' }
  ];

  let REDUCED = false;

  // ---------- utils ----------
  function getReducedMotion() {
    const mq = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
    return !!(mq && mq.matches);
  }

  function setText(el, str) {
    if (el) el.textContent = str;
  }

  function formatJWT(jwt) {
    return 'HEADER ' + JSON.stringify(jwt.header) + '\n' +
           'PAYLOAD ' + JSON.stringify(jwt.payload) + '\n' +
           'SIG ' + jwt.signature.substring(0, 28) + '…';
  }

  function shortHash(h) {
    if (!h) return '—';
    return h.substring(0, 10) + '…';
  }

  // real SHA-256 via Web Crypto when possible; deterministic fallback
  function simpleHash(str) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return ('0000000' + h.toString(16)).slice(-8) +
           ('0000000' + (h ^ 0xdeadbeef).toString(16)).slice(-8);
  }

  function computeHash(input, cb) {
    if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
      const enc = new TextEncoder().encode(input);
      window.crypto.subtle.digest('SHA-256', enc).then(function (buf) {
        const arr = new Uint8Array(buf);
        const hex = Array.prototype.map.call(arr, function (b) { return ('00' + b.toString(16)).slice(-2); }).join('');
        cb(hex);
      }).catch(function () {
        cb(simpleHash(input));
      });
    } else {
      // sync fallback
      setTimeout(function () { cb(simpleHash(input)); }, 0);
    }
  }

  // ---------- DOM refs (declared early) ----------
  let jwtEl, issuerStatus, v1Status, v2Status, v1Detail, v2Detail;
  let aNoneStatus, aHsStatus, aJkuStatus;
  let replayBtn;
  let ledgerEl, rootEl, appendBtn, resetBtn;
  let tabBinary, tabHelm, panelBinary, panelHelm;
  let copyBtns;

  let chainTimer = null;
  let currentAudit = [];
  let currentRoot = '';

  // ---------- reduced motion ----------
  function applyReducedGuards() {
    REDUCED = getReducedMotion();
    const crt = document.querySelector('.v-crt');
    const grain = document.querySelector('.v-grain');
    if (REDUCED) {
      if (crt) crt.style.animation = 'none';
      if (grain) grain.style.opacity = '0.03';
    }
  }

  // ---------- trust chain (hero) ----------
  function setIssuerState(text, jwtText) {
    setText(issuerStatus, text);
    if (jwtText && jwtEl) setText(jwtEl, jwtText);
    if (text && text.indexOf('ISSUED') !== -1) {
      issuerStatus.className = 'status issued';
    } else if (text && text.indexOf('ISSUING') !== -1) {
      issuerStatus.className = 'status idle';
    }
  }

  function setVerifier(node, statusText, detailText) {
    if (node === 'v1') {
      setText(v1Status, statusText);
      if (detailText) setText(v1Detail, detailText);
      if (statusText.indexOf('VERIFIED') !== -1) {
        v1Status.className = 'status verified';
      } else {
        v1Status.className = 'status idle';
      }
    } else if (node === 'v2') {
      setText(v2Status, statusText);
      if (detailText) setText(v2Detail, detailText);
      if (statusText.indexOf('VERIFIED') !== -1) {
        v2Status.className = 'status verified';
      } else {
        v2Status.className = 'status idle';
      }
    }
  }

  function setAllAttackersRejected() {
    setText(aNoneStatus, 'REJECTED');
    aNoneStatus.className = 'status rejected';
    setText(aHsStatus, 'REJECTED');
    aHsStatus.className = 'status rejected';
    setText(aJkuStatus, 'REJECTED');
    aJkuStatus.className = 'status rejected';
  }

  function resetChainVisual() {
    if (jwtEl) setText(jwtEl, '—');
    setText(issuerStatus, 'IDLE');
    issuerStatus.className = 'status idle';
    setText(v1Status, '—');
    v1Status.className = 'status idle';
    setText(v2Status, '—');
    v2Status.className = 'status idle';
    if (v1Detail) setText(v1Detail, '—');
    if (v2Detail) setText(v2Detail, '—');
    setText(aNoneStatus, '—');
    aNoneStatus.className = 'status idle';
    setText(aHsStatus, '—');
    aHsStatus.className = 'status idle';
    setText(aJkuStatus, '—');
    aJkuStatus.className = 'status idle';
  }

  function stopChainTimer() {
    if (chainTimer) {
      clearTimeout(chainTimer);
      chainTimer = null;
    }
  }

  function runChainDemo() {
    stopChainTimer();
    resetChainVisual();
    setAllAttackersRejected(); // always visible as final reject

    if (REDUCED) {
      // static final resolved state, no animation
      const jwtStr = formatJWT(SAMPLE_JWT);
      setText(jwtEl, jwtStr);
      setText(issuerStatus, 'ISSUED RS256');
      issuerStatus.className = 'status issued';
      setVerifier('v1', 'VERIFIED', 'JWKS OK · kid=a1b2c3d4');
      setVerifier('v2', 'VERIFIED', 'JWKS OK · kid=a1b2c3d4');
      setAllAttackersRejected();
      return;
    }

    // animated loop sequence
    let step = 0;
    const delays = [420, 620, 520, 580, 420, 420, 380, 520];

    function next() {
      stopChainTimer();
      if (REDUCED) { runChainDemo(); return; }

      switch (step) {
        case 0:
          setIssuerState('ISSUING…', '—');
          chainTimer = setTimeout(next, delays[0]);
          break;
        case 1: {
          const j = formatJWT(SAMPLE_JWT);
          setIssuerState('ISSUED RS256', j);
          setVerifier('v1', 'VERIFYING…', 'fetch /.well-known/jwks.json');
          chainTimer = setTimeout(next, delays[1]);
          break;
        }
        case 2:
          setVerifier('v1', 'VERIFIED', 'JWKS OK · kid=a1b2c3d4');
          setVerifier('v2', 'VERIFYING…', 'fetch /.well-known/jwks.json');
          chainTimer = setTimeout(next, delays[2]);
          break;
        case 3:
          setVerifier('v2', 'VERIFIED', 'JWKS OK · kid=a1b2c3d4');
          chainTimer = setTimeout(next, delays[3]);
          break;
        case 4:
          // attacker none
          setText(aNoneStatus, 'REJECTED');
          aNoneStatus.className = 'status rejected';
          chainTimer = setTimeout(next, delays[4]);
          break;
        case 5:
          // hs256 confusion
          setText(aHsStatus, 'REJECTED');
          aHsStatus.className = 'status rejected';
          chainTimer = setTimeout(next, delays[5]);
          break;
        case 6:
          // forged jku
          setText(aJkuStatus, 'REJECTED');
          aJkuStatus.className = 'status rejected';
          chainTimer = setTimeout(next, delays[6]);
          break;
        case 7:
          // pause then loop
          chainTimer = setTimeout(function () {
            runChainDemo();
          }, delays[7]);
          break;
        default:
          runChainDemo();
      }
      step = (step + 1) % 8;
    }

    next();
  }

  function initTrustChain() {
    jwtEl = document.getElementById('jwt-display');
    issuerStatus = document.getElementById('issuer-status');
    v1Status = document.getElementById('v1-status');
    v2Status = document.getElementById('v2-status');
    v1Detail = document.getElementById('v1-detail');
    v2Detail = document.getElementById('v2-detail');
    aNoneStatus = document.getElementById('a-none-status');
    aHsStatus = document.getElementById('a-hs-status');
    aJkuStatus = document.getElementById('a-jku-status');
    replayBtn = document.getElementById('chain-replay');

    if (replayBtn) {
      replayBtn.addEventListener('click', function () {
        runChainDemo();
      });
    }

    // initial static attackers always show rejected label
    setAllAttackersRejected();
    runChainDemo();
  }

  // ---------- audit ledger ----------
  function renderLedger() {
    if (!ledgerEl) return;
    ledgerEl.innerHTML = '';

    const head = document.createElement('div');
    head.className = 'ledger-head';
    head.innerHTML = '<div>TIMESTAMP</div><div>EVENT</div><div>IP</div><div>PREV</div><div>HASH</div>';
    ledgerEl.appendChild(head);

    for (let i = 0; i < currentAudit.length; i++) {
      const row = currentAudit[i];
      const div = document.createElement('div');
      div.className = 'ledger-row';
      div.innerHTML =
        '<div>' + row.ts + '</div>' +
        '<div>' + row.event + '</div>' +
        '<div>' + row.ip + '</div>' +
        '<div class="hash">' + shortHash(row.prev) + '</div>' +
        '<div class="hash">' + shortHash(row.hash) + '</div>';
      ledgerEl.appendChild(div);
    }

    if (rootEl) {
      setText(rootEl, 'ROOT: ' + (currentRoot ? shortHash(currentRoot) + '  (full: ' + currentRoot.substring(0, 16) + '…)' : '—'));
    }
  }

  function seedAudit() {
    currentAudit = [];
    currentRoot = '';
    let prev = '00000000000000000000000000000000';

    for (let i = 0; i < AUDIT_SEED.length; i++) {
      const seed = AUDIT_SEED[i];
      const input = prev + '|' + seed.ts + '|' + seed.event + '|' + seed.ip;
      const h = simpleHash(input);  // sync for init reliability (real sha used on appends)
      const entry = {
        ts: seed.ts,
        event: seed.event,
        ip: seed.ip,
        prev: prev,
        hash: h
      };
      currentAudit.push(entry);
      prev = h;
    }
    currentRoot = currentAudit.length ? currentAudit[currentAudit.length - 1].hash : '';
    renderLedger();
  }

  function appendAuditEvent() {
    let last = currentAudit.length ? currentAudit[currentAudit.length - 1] : null;
    let prev = last ? last.hash : '00000000000000000000000000000000';
    if (!last) {
      seedAudit();
      last = currentAudit.length ? currentAudit[currentAudit.length - 1] : null;
      prev = last ? last.hash : '00000000000000000000000000000000';
    }
    const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const events = ['login_success', 'token_refresh', '2fa_verify', 'fingerprint_anomaly', 'session_revoke'];
    const ev = events[Math.floor(Math.random() * events.length)];
    const ip = (Math.random() > 0.5) ? '203.0.113.' + Math.floor(10 + Math.random() * 80) : '198.51.100.' + Math.floor(10 + Math.random() * 80);

    const input = prev + '|' + now + '|' + ev + '|' + ip;
    computeHash(input, function (h) {
      currentAudit.push({ ts: now, event: ev, ip: ip, prev: prev, hash: h });
      currentRoot = h;
      renderLedger();
    });
  }

  function resetAudit() {
    seedAudit();
  }

  function initAudit() {
    ledgerEl = document.getElementById('audit-ledger');
    rootEl = document.getElementById('audit-root');
    appendBtn = document.getElementById('audit-append');
    resetBtn = document.getElementById('audit-reset');

    seedAudit();

    if (appendBtn) {
      appendBtn.addEventListener('click', function () {
        appendAuditEvent();
      });
    }
    if (resetBtn) {
      resetBtn.addEventListener('click', function () {
        resetAudit();
      });
    }
  }

  // ---------- quickstart tabs + copy ----------
  function initTabs() {
    tabBinary = document.getElementById('tab-binary');
    tabHelm = document.getElementById('tab-helm');
    panelBinary = document.getElementById('panel-binary');
    panelHelm = document.getElementById('panel-helm');

    function show(which) {
      if (which === 'binary') {
        if (panelBinary) panelBinary.style.display = '';
        if (panelHelm) panelHelm.style.display = 'none';
        if (tabBinary) { tabBinary.classList.add('is-active'); tabBinary.setAttribute('aria-selected', 'true'); }
        if (tabHelm) { tabHelm.classList.remove('is-active'); tabHelm.setAttribute('aria-selected', 'false'); }
      } else {
        if (panelBinary) panelBinary.style.display = 'none';
        if (panelHelm) panelHelm.style.display = '';
        if (tabBinary) { tabBinary.classList.remove('is-active'); tabBinary.setAttribute('aria-selected', 'false'); }
        if (tabHelm) { tabHelm.classList.add('is-active'); tabHelm.setAttribute('aria-selected', 'true'); }
      }
    }

    if (tabBinary) tabBinary.addEventListener('click', function () { show('binary'); });
    if (tabHelm) tabHelm.addEventListener('click', function () { show('helm'); });
  }

  function copyText(text, btn) {
    const orig = btn.textContent;
    function done(ok) {
      btn.textContent = ok ? 'COPIED' : 'ERR';
      setTimeout(function () { btn.textContent = orig; }, 900);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }).catch(function () { done(false); });
    } else {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      let ok = false;
      // execCommand throws in a sandboxed frame rather than returning false.
      // Either way the outcome reaches the caller through `ok`.
      try { ok = document.execCommand('copy'); } catch { /* handled by ok staying false */ }
      document.body.removeChild(ta);
      done(ok);
    }
  }

  function initCopy() {
    copyBtns = document.querySelectorAll('.copy-btn');
    for (let i = 0; i < copyBtns.length; i++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          const targetId = btn.getAttribute('data-copy-target');
          const pre = document.getElementById(targetId);
          if (!pre) return;
          const txt = pre.textContent || pre.innerText || '';
          copyText(txt.trim(), btn);
        });
      })(copyBtns[i]);
    }
  }

  // ---------- keyboard + a11y extras ----------
  function initKeyboard() {
    // ? focuses replay when hero visible
    document.addEventListener('keydown', function (e) {
      if (e.key === '?' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        if (replayBtn) replayBtn.focus();
      }
      if (e.key === 'Escape') {
        stopChainTimer();
      }
    });

    // ensure all buttons have type if not
    const allBtns = document.querySelectorAll('button');
    for (let i = 0; i < allBtns.length; i++) {
      if (!allBtns[i].getAttribute('type')) allBtns[i].setAttribute('type', 'button');
    }
  }

  function initCTAScroll() {
    // anchors already wired in markup
  }

  // ---------- init ----------
  function init() {
    applyReducedGuards();

    initTrustChain();
    initAudit();
    initTabs();
    initCopy();
    initKeyboard();
    initCTAScroll();

    // re-eval reduced on change (no loops restart)
    if (window.matchMedia) {
      const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
      if (mq.addEventListener) {
        mq.addEventListener('change', function () {
          applyReducedGuards();
          // refresh chain to correct static/anim mode
          runChainDemo();
        });
      }
    }

    // final state hint for static (already handled)
    // ensure attackers are labelled even before first cycle
    setTimeout(function () {
      if (aNoneStatus && aNoneStatus.textContent === '—') {
        setAllAttackersRejected();
      }
    }, 60);
  }

  // boot
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
