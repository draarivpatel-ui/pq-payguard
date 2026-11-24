/*
 * Browser wiring for PQ PayGuard. All heavy logic lives in src/ modules;
 * this file only binds them to the DOM. No network call happens at load.
 */
(function () {
  'use strict';

  var K = PQPG.keccak;
  var A = PQPG.abi;
  var CH = PQPG.chain;
  var R = PQPG.risk;
  var C = PQPG.commit;
  var SIM = PQPG.sim;
  var RPC = PQPG.rpc;
  var W = PQPG.wallet;

  var $ = function (id) { return document.getElementById(id); };
  var live = $('a11y-live');

  function say(msg) {
    if (live) live.textContent = msg;
  }

  // Tell the decision pipeline (src/pipeline.js) that page state changed.
  function emit(source) {
    try {
      document.dispatchEvent(new CustomEvent('pqpg:update', { detail: { source: source } }));
    } catch (e) { /* older engines: pipeline re-renders on its own inputs */ }
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ---- theme -----------------------------------------------------------

  var themeBtn = $('theme-toggle');
  function applyTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    themeBtn.textContent = t === 'dark' ? 'Light' : 'Dark';
    try { localStorage.setItem('pqpg-theme', t); } catch (e) { /* private mode */ }
  }
  var savedTheme = null;
  try { savedTheme = localStorage.getItem('pqpg-theme'); } catch (e) { /* ignored */ }
  applyTheme(savedTheme === 'light' ? 'light' : 'dark');
  themeBtn.addEventListener('click', function () {
    applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });

  // ---- demo actors -------------------------------------------------------

  var ACTORS = {
    payer: '0x0000000000000000000000000000000000000Aa1',
    operator: '0x00000000000000000000000000000000000000D4',
    guardian: '0x00000000000000000000000000000000000006C1',
    recipient: '0x0000000000000000000000000000000000000Bb2',
    merchant2: '0x0000000000000000000000000000000000000Cc3',
    stranger: '0x0000000000000000000000000000000000000Ee5'
  };
  var SIM_CONTRACT = '0x' + '11'.repeat(20);
  var SIM_START = 1764000000; // deterministic start time

  // ---- risk score panel ---------------------------------------------------

  var schemeSel = $('in-scheme');
  Object.keys(R.SCHEME_BASE).forEach(function (s) {
    var o = document.createElement('option');
    o.value = s;
    o.textContent = s + ' (base ' + R.SCHEME_BASE[s] + ')';
    schemeSel.appendChild(o);
  });
  schemeSel.value = 'secp256k1';

  var currentScore = null;

  function refreshScore() {
    try {
      currentScore = R.exposureScore({
        scheme: schemeSel.value,
        keyRevealed: $('in-revealed').checked,
        deprecated: $('in-deprecated').checked,
        valueTusd: Number($('in-value').value || 0),
        ageDays: Number($('in-age').value || 0)
      });
    } catch (e) {
      currentScore = null;
      $('score-num').textContent = '-';
      $('score-tier').textContent = 'invalid';
      $('factor-list').innerHTML = '';
      emit('score');
      return;
    }
    $('score-num').textContent = String(currentScore.score);
    var tierEl = $('score-tier');
    tierEl.textContent = currentScore.tierName;
    tierEl.className = 'score-tier ' + currentScore.tierName;
    $('factor-list').innerHTML = currentScore.factors.map(function (f) {
      return '<li><span>' + esc(f.label) + '</span><b>+' + f.points + '</b></li>';
    }).join('');
    refreshHashes();
    emit('score');
  }

  ['in-scheme', 'in-value', 'in-age', 'in-revealed', 'in-deprecated'].forEach(function (id) {
    $(id).addEventListener('input', refreshScore);
    $(id).addEventListener('change', refreshScore);
  });

  // ---- hash + calldata panel ----------------------------------------------

  var hashSeq = 0;
  async function refreshHashes() {
    var seq = ++hashSeq;
    if (!currentScore) return;
    var contract = ($('in-contract').value || '').trim() || SIM_CONTRACT;
    var payer = ($('in-payer').value || '').trim();
    var recipient = ($('in-recipient').value || '').trim();
    var sessionId = Number($('in-session').value || 0);
    var deadline = Math.floor(Date.now() / 1000) + Number($('in-deadline').value || 24) * 3600;
    var amountRaw;
    try {
      amountRaw = CH.parseTokenUnits($('in-amount').value, CH.TUSD8.decimals);
    } catch (e) {
      $('out-calldata').textContent = 'amount error: ' + e.message;
      return;
    }
    if (!CH.isValidAddress(contract) || !CH.isValidAddress(payer) || !CH.isValidAddress(recipient)) {
      $('out-calldata').textContent = 'addresses must be 0x + 40 hex chars';
      return;
    }
    var att = await C.buildAttestation({
      payer: payer, recipient: recipient, amountRaw: amountRaw,
      score: currentScore.score, tier: currentScore.tierName, scheme: currentScore.scheme,
      factors: currentScore.factors, sessionId: sessionId,
      nonce: seq, issuedAt: Math.floor(Date.now() / 1000)
    });
    if (seq !== hashSeq) return; // stale input round
    var com = C.computeCommitment({
      chainId: CH.NETWORK.chainId, contractAddress: contract,
      sessionId: sessionId, payer: payer, recipient: recipient,
      amountRaw: amountRaw, riskScore: currentScore.score,
      attestationHash: att.attestationHash, deadline: deadline
    });
    var calldata = A.encodeCall(CH.ESCROW_ABI.createEscrow, [
      BigInt(sessionId), recipient, amountRaw, currentScore.score,
      att.attestationHash, com, BigInt(deadline)
    ]);
    $('out-att').textContent = att.attestationHash;
    $('out-com').textContent = com;
    $('out-calldata').textContent = calldata;
  }

  ['in-contract', 'in-session', 'in-payer', 'in-recipient', 'in-amount', 'in-deadline'].forEach(function (id) {
    $(id).addEventListener('input', refreshHashes);
  });

  $('btn-copy-calldata').addEventListener('click', function () {
    var text = $('out-calldata').textContent;
    var done = function () { say('Calldata copied'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { say('Copy failed'); });
    } else {
      say('Clipboard unavailable');
    }
  });

  // ---- simulator -----------------------------------------------------------

  var sim = new SIM.PayGuardSim({
    chainId: CH.NETWORK.chainId,
    contractAddress: SIM_CONTRACT,
    now: SIM_START
  });
  sim.mint(ACTORS.payer, 100_000_000_000n); // demo balance, 100k tUSD8

  // Read only handles for the decision pipeline view.
  PQPG.view = {
    sim: sim,
    actors: ACTORS,
    score: function () { return currentScore; }
  };

  var actorSel = $('sim-actor');
  var guardianSel = $('ses-guardian');
  var operatorSel = $('ses-operator');
  var recipientSel = $('esc-recipient');
  var actorNames = ['payer', 'operator', 'guardian', 'recipient', 'merchant2', 'stranger'];
  actorNames.forEach(function (n) {
    var o = document.createElement('option');
    o.value = ACTORS[n];
    o.textContent = n + ' ' + CH.shortHash(ACTORS[n], 8, 6);
    actorSel.appendChild(o);
  });
  actorSel.value = ACTORS.payer;

  function fillSelect(sel, options, includeNone) {
    sel.innerHTML = '';
    if (includeNone) {
      var none = document.createElement('option');
      none.value = '';
      none.textContent = includeNone;
      sel.appendChild(none);
    }
    options.forEach(function (o) {
      var el = document.createElement('option');
      el.value = o.value;
      el.textContent = o.label;
      sel.appendChild(el);
    });
  }

  fillSelect(guardianSel, [{ value: ACTORS.guardian, label: 'guardian' }], 'none (High tier blocked)');
  fillSelect(operatorSel, [{ value: ACTORS.operator, label: 'operator' }], 'none (payer only)');
  fillSelect(recipientSel, [
    { value: ACTORS.recipient, label: 'recipient' },
    { value: ACTORS.merchant2, label: 'merchant2' }
  ]);

  function actorName(addr) {
    var n = Object.keys(ACTORS).find(function (k) { return ACTORS[k] === addr; });
    return n || CH.shortHash(addr, 8, 6);
  }

  function fmtTime(t) {
    return new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  }

  function fmtAmt(raw) {
    return CH.formatTokenUnits(raw, CH.TUSD8.decimals) + ' tUSD8';
  }

  function simError(e) {
    var msg = (e && e.code) ? e.code : String(e && e.message || e);
    say('Reverted: ' + msg);
    sim.audit.push({ event: 'revert', at: sim.now, reason: msg });
    renderSim();
  }

  function renderSim() {
    $('sim-now').textContent = fmtTime(sim.now) + ' (' + sim.now + ')';

    // sessions
    var sl = $('session-list');
    if (sim.sessions.size === 0) {
      sl.innerHTML = '<div class="empty">No sessions yet. Create one to set the spend policy.</div>';
    } else {
      sl.innerHTML = [...sim.sessions.entries()].map(function (kv) {
        var id = kv[0], s = kv[1];
        var flags = '';
        if (s.revoked) flags += '<span class="flag on">revoked</span>';
        if (s.paused) flags += '<span class="flag on">paused</span>';
        if (sim.now >= s.expiry) flags += '<span class="flag on">expired</span>';
        if (!flags) flags = '<span class="flag">active</span>';
        return '<div class="ses-card">' +
          '<div class="ses-head"><span class="id">session ' + id + '</span>' +
          '<span class="ses-flags">' + flags + '</span></div>' +
          '<div class="ses-meta">' +
          '<span>payer <b>' + esc(actorName(s.payer)) + '</b> operator <b>' + (s.operator === SIM.ZERO ? 'none' : esc(actorName(s.operator))) + '</b> guardian <b>' + (s.guardian === SIM.ZERO ? 'none' : esc(actorName(s.guardian))) + '</b></span>' +
          '<span>per tx cap <b>' + fmtAmt(s.maxPerTx) + '</b> cumulative <b>' + fmtAmt(s.spent) + ' / ' + fmtAmt(s.capTotal) + '</b></span>' +
          '<span>expires <b>' + fmtTime(s.expiry) + '</b> delays <b>' + s.mediumDelay + 's / ' + s.highDelay + 's</b></span>' +
          '</div>' +
          '<div class="esc-actions">' +
          (s.paused
            ? '<button class="btn btn-ghost sm" data-act="unpause" data-sid="' + id + '">Unpause</button>'
            : '<button class="btn btn-ghost sm" data-act="pause" data-sid="' + id + '">Pause</button>') +
          '<button class="btn btn-ghost sm" data-act="revoke-session" data-sid="' + id + '">Revoke session</button>' +
          '</div></div>';
      }).join('');
    }

    // session picker for escrow form
    var escSes = $('esc-session');
    var prev = escSes.value;
    fillSelect(escSes, [...sim.sessions.keys()].map(function (id) {
      return { value: String(id), label: 'session ' + id };
    }));
    if (prev) escSes.value = prev;

    // escrows
    var el = $('escrow-list');
    if (sim.escrows.size === 0) {
      el.innerHTML = '<div class="empty">No escrows yet.</div>';
    } else {
      el.innerHTML = [...sim.escrows.entries()].map(function (kv) {
        var id = kv[0], e = kv[1];
        var tierName = CH.TIER_NAMES[e.tier];
        var statusName = CH.STATUS_NAMES[e.status];
        var blocker = e.status === 1 ? sim.releaseBlocker(id) : '';
        var actions = '';
        if (e.status === 1) {
          if (e.tier === 2 && !e.guardianApproved) {
            actions += '<button class="btn btn-ghost sm" data-act="approve" data-eid="' + id + '">Guardian approve</button>';
          }
          actions += '<button class="btn btn-primary sm" data-act="release" data-eid="' + id + '">Release</button>';
          actions += '<button class="btn btn-ghost sm" data-act="revoke" data-eid="' + id + '">Revoke</button>';
        }
        var blockerHtml = blocker
          ? '<div class="esc-blocker">release gate says ' + esc(blocker) + '</div>'
          : (e.status === 1 ? '<div class="esc-blocker" style="color:var(--good)">gate open, release allowed now</div>' : '');
        return '<div class="esc-card">' +
          '<div class="esc-card-top">' +
          '<span class="id">escrow ' + id + '</span>' +
          '<span class="tier tier-' + tierName.slice(0, 4) + '">' + tierName + '</span>' +
          '<span class="status ' + statusName + '">' + statusName + '</span>' +
          '<span class="id">' + fmtAmt(e.amount) + '</span>' +
          '</div>' +
          '<div class="esc-meta">' +
          '<span>score <b>' + e.riskScore + '</b> session <b>' + e.sessionId + '</b> ' +
          esc(actorName(e.payer)) + ' -> ' + esc(actorName(e.recipient)) + '</span>' +
          '<span>unlock <b>' + (e.releaseNotBefore >= Number.MAX_SAFE_INTEGER ? 'never (quarantined)' : fmtTime(e.releaseNotBefore)) + '</b> deadline <b>' + fmtTime(e.deadline) + '</b></span>' +
          '<span>attestation <b>' + CH.shortHash(e.attestationHash) + '</b> commitment <b>' + CH.shortHash(e.commitmentHash) + '</b></span>' +
          '</div>' + blockerHtml +
          (actions ? '<div class="esc-actions">' + actions + '</div>' : '') +
          '</div>';
      }).join('');
    }

    // audit
    $('audit-body').innerHTML = sim.audit.slice(-400).map(function (a) {
      var detail = Object.keys(a).filter(function (k) { return k !== 'event' && k !== 'at'; })
        .map(function (k) { return k + '=' + esc(String(a[k])).slice(0, 44); }).join(' ');
      return '<tr><td>' + a.at + '</td><td>' + esc(a.event) + '</td><td>' + detail + '</td></tr>';
    }).join('');
    emit('sim');
  }

  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('button[data-act]');
    if (!b) return;
    var act = b.getAttribute('data-act');
    var actor = actorSel.value;
    try {
      if (act === 'pause') sim.setSessionPaused(actor, Number(b.getAttribute('data-sid')), true);
      else if (act === 'unpause') sim.setSessionPaused(actor, Number(b.getAttribute('data-sid')), false);
      else if (act === 'revoke-session') sim.revokeSession(actor, Number(b.getAttribute('data-sid')));
      else if (act === 'approve') sim.guardianApprove(actor, Number(b.getAttribute('data-eid')));
      else if (act === 'release') sim.release(actor, Number(b.getAttribute('data-eid')));
      else if (act === 'revoke') sim.revokeEscrow(actor, Number(b.getAttribute('data-eid')));
      say(act + ' applied');
    } catch (e) { simError(e); return; }
    renderSim();
  });

  $('btn-warp').addEventListener('click', function () {
    sim.advanceTime(Number($('sim-warp').value));
    say('Time advanced');
    renderSim();
  });

  $('session-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    try {
      var maxPerTx = CH.parseTokenUnits($('ses-max').value, CH.TUSD8.decimals);
      var capTotal = CH.parseTokenUnits($('ses-cap').value, CH.TUSD8.decimals);
      var sid = sim.createSession(actorSel.value, {
        operator: $('ses-operator').value || null,
        guardian: $('ses-guardian').value || null,
        maxPerTx: maxPerTx,
        capTotal: capTotal,
        expiry: sim.now + Number($('ses-expiry').value) * 86400,
        mediumDelay: Number($('ses-med').value) * 60,
        highDelay: Number($('ses-high').value) * 60
      });
      // payer approves the contract for the cumulative cap, like on chain
      var s = sim.sessions.get(sid);
      sim.approve(s.payer, sim.contractAddress, capTotal);
      say('Session ' + sid + ' created');
    } catch (e) { simError(e); return; }
    renderSim();
  });

  $('sim-escrow-form').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    try {
      var sid = Number($('esc-session').value || 0);
      var recipient = $('esc-recipient').value;
      var amount = CH.parseTokenUnits($('esc-amount').value, CH.TUSD8.decimals);
      var scoreInput = $('esc-score').value;
      var score = scoreInput === '' ? (currentScore ? currentScore.score : null) : Number(scoreInput);
      if (score === null || !Number.isInteger(score) || score < 0 || score > 100) {
        throw new Error('score must be an integer 0-100');
      }
      var s = sim.sessions.get(sid);
      if (!s) throw new Error('pick a session first');
      var deadline = sim.now + Number($('esc-deadline').value) * 3600;
      var att = await C.buildAttestation({
        payer: s.payer, recipient: recipient, amountRaw: amount,
        score: score, tier: CH.TIER_NAMES[SIM.tierOf(score)], scheme: currentScore ? currentScore.scheme : 'custom',
        factors: currentScore ? currentScore.factors : [], sessionId: sid,
        nonce: String(sim.nextEscrowId), issuedAt: sim.now
      });
      var com = sim.computeCommitment({
        sessionId: sid, payer: s.payer, recipient: recipient,
        amountRaw: amount, riskScore: score,
        attestationHash: att.attestationHash, deadline: deadline
      });
      var eid = sim.createEscrow(actorSel.value, sid, {
        recipient: recipient, amount: amount, riskScore: score,
        attestationHash: att.attestationHash, commitmentHash: com, deadline: deadline
      });
      say('Escrow ' + eid + ' funded');
    } catch (e) { simError(e); return; }
    renderSim();
  });

  $('btn-export').addEventListener('click', function () {
    var blob = new Blob([sim.exportAudit()], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'pq-payguard-audit.json';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    say('Audit exported');
  });

  // ---- network panel --------------------------------------------------------

  function kvRender(el, pairs) {
    el.innerHTML = pairs.map(function (p) {
      return '<dt>' + esc(p[0]) + '</dt><dd>' + esc(p[1]) + '</dd>';
    }).join('');
  }

  $('btn-probe').addEventListener('click', async function () {
    var status = $('probe-status');
    status.textContent = 'probing...';
    status.className = 'net-status';
    var account = ($('rpc-account').value || '').trim() || undefined;
    var r = await RPC.probeTestnet({ account: account });
    status.textContent = r.live ? 'live' : 'offline fallback';
    status.className = 'net-status ' + (r.live ? 'ok' : 'warn');
    kvRender($('probe-out'), [
      ['mode', r.mode + (r.fallbackReason ? ' (' + r.fallbackReason + ')' : '')],
      ['chainId', r.chainId + ' (' + r.chainIdHex + ') ' + (r.chainIdMatches ? 'match' : 'MISMATCH')],
      ['block', String(r.blockNumber)],
      ['tUSD8', r.token.symbol + ' ' + r.token.decimals + ' decimals'],
      ['supply', r.token.totalSupplyFormatted + ' ' + r.token.symbol],
      ['account', r.account || 'not provided'],
      ['balance', r.accountBalanceFormatted === null ? '-' : r.accountBalanceFormatted + ' ' + r.token.symbol]
    ]);
    say('Probe finished ' + r.mode);
  });

  var walletAccount = null;
  $('btn-connect').addEventListener('click', async function () {
    try {
      var res = await W.connectWallet();
      walletAccount = res.account;
      kvRender($('wallet-out'), [
        ['account', res.account || 'none'],
        ['chainId', res.chainId + ' (' + res.chainIdNumber + ')'],
        ['on aevum', res.onAevum ? 'yes' : 'no, use switch']
      ]);
      say('Wallet connected');
    } catch (e) {
      kvRender($('wallet-out'), [['status', String(e.message || e)]]);
      say('Wallet unavailable');
    }
  });

  $('btn-switch').addEventListener('click', async function () {
    try {
      var res = await W.ensureAevumNetwork();
      kvRender($('wallet-out'), [
        ['switch', res.added ? 'chain added then switched' : 'switched'],
        ['params', CH.NETWORK.chainIdHex + ' ' + CH.NETWORK.rpcUrl]
      ]);
      say('On Aevum');
    } catch (e) {
      kvRender($('wallet-out'), [['status', String(e.message || e)]]);
      say('Switch failed or no wallet');
    }
  });

  $('btn-live-read').addEventListener('click', async function () {
    var status = $('live-status');
    var contract = ($('live-contract').value || '').trim();
    if (!CH.isValidAddress(contract)) {
      status.textContent = 'bad address';
      status.className = 'net-status err';
      return;
    }
    status.textContent = 'reading...';
    status.className = 'net-status';
    var eid = Number($('live-escrow').value || 0);
    try {
      var count = await RPC.readEscrowCount(contract);
      var blocker = await RPC.readReleaseBlocker(contract, eid);
      status.textContent = 'ok';
      status.className = 'net-status ok';
      kvRender($('live-out'), [
        ['nextEscrowId', String(count)],
        ['releaseBlocker(' + eid + ')', blocker === '' ? 'gate open' : blocker],
        ['contract', contract],
        ['explorer', CH.explorerAddressUrl(contract)]
      ]);
      say('On chain read complete');
    } catch (e) {
      status.textContent = 'failed';
      status.className = 'net-status err';
      kvRender($('live-out'), [['error', String(e.message || e)]]);
    }
  });

  // ---- selftest hook (?selftest) ---------------------------------------------

  if (/[?&]selftest\b/.test(location.search)) {
    window.addEventListener('load', function () {
      setTimeout(function () {
        var report = { errors: window.__pqpgErrors || [], fetches: window.__pqpgFetch || [] };
        try {
          var s = R.exposureScore({ scheme: 'rsa-2048', keyRevealed: true, valueTusd: 12000, ageDays: 500, deprecated: false });
          report.scoreCheck = s.score === 100 && s.tier === 3;
          var t = new SIM.PayGuardSim({ now: 1000 });
          t.mint(ACTORS.payer, 1000000n);
          var sid = t.createSession(ACTORS.payer, {
            operator: null, guardian: ACTORS.guardian, maxPerTx: 500000n, capTotal: 2000000n,
            expiry: 1000 + 86400, mediumDelay: 900, highDelay: 14400
          });
          t.approve(ACTORS.payer, t.contractAddress, 2000000n);
          var com = t.computeCommitment({
            sessionId: sid, payer: ACTORS.payer, recipient: ACTORS.recipient,
            amountRaw: 100000n, riskScore: 10,
            attestationHash: '0x' + 'ab'.repeat(32), deadline: 1000 + 3600
          });
          var eid = t.createEscrow(ACTORS.payer, sid, {
            recipient: ACTORS.recipient, amount: 100000n, riskScore: 10,
            attestationHash: '0x' + 'ab'.repeat(32), commitmentHash: com, deadline: 1000 + 3600
          });
          t.release(ACTORS.recipient, eid);
          report.simCheck = t.escrows.get(eid).status === 2 && t.balanceOf(ACTORS.recipient) === 100000n;
          report.scrollWidth = document.documentElement.scrollWidth;
          report.innerWidth = window.innerWidth;
          report.overflowX = document.documentElement.scrollWidth > document.documentElement.clientWidth;
        } catch (e) {
          report.errors.push('selftest:' + (e && e.message || e));
        }
        $('selftest-report').textContent = JSON.stringify(report);
        document.title = 'SELFTEST ' + (report.errors.length === 0 ? 'OK' : 'FAIL');
      }, 600);
    });
  }

  // ---- boot -------------------------------------------------------------------

  refreshScore();
  renderSim();
})();
