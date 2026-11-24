/*
 * Decision pipeline view for PQ PayGuard.
 *
 * Four stages, read left to right, all driven by real page state:
 *   1. Risk tier meter     the score the next escrow will commit, its tier
 *                          and the release path the contract assigns to it
 *   2. Spend cap gate      a preflight of the session, actor, per tx cap,
 *                          cumulative cap, score, guardian, deadline,
 *                          allowance and balance checks in the same order
 *                          PayGuardSim.createEscrow runs them
 *   3. Escrow state        the latest escrow in the simulator and the exact
 *                          releaseBlocker the simulator reports for it
 *   4. WOTS receipt        the last receipt build or verify result, with the
 *                          one time leaf map of the signing wallet
 *
 * derive() is pure and runs under node for the test suite. The DOM binding
 * at the bottom only reads state that ui.js and workbench.js publish on
 * PQPG.view and PQPG.workbench; it never invents a verdict. Stages that have
 * nothing to show yet say so instead of showing a pass.
 *
 * The scheme class chip classifies the receiving scheme under the score
 * model. The escrow contract itself performs no post quantum signatures.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.pipeline = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const TIER_NAMES = ['low', 'medium', 'high', 'critical'];
  const ZERO = '0x0000000000000000000000000000000000000000';

  // Post quantum signature families in the score model (src/risk.js).
  const PQ_SCHEMES = Object.freeze([
    'falcon-512', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87',
    'slh-dsa-128s', 'slh-dsa-192s', 'slh-dsa-256s', 'hash-only'
  ]);

  // Which pipeline stage each attack in src/attacks.js exercises.
  const ATTACK_STAGE = Object.freeze({
    'shor-drain': 'risk',
    'domain': 'risk',
    'limit-bypass': 'cap',
    'replay': 'escrow',
    'leaf-reuse': 'receipt',
    'merkle-tamper': 'receipt'
  });
  const ATTACK_LABEL = Object.freeze({
    'shor-drain': 'Shor drain',
    'domain': 'domain forgery',
    'limit-bypass': 'limit bypass',
    'replay': 'replay',
    'leaf-reuse': 'leaf reuse',
    'merkle-tamper': 'merkle tamper'
  });
  const HELD = ['REJECTED', 'BLOCKED', 'PROTECTED'];

  // Same bounds as src/risk.js and PQPayGuardEscrow.sol.
  function tierOf(score) {
    if (score <= 29) return 0;
    if (score <= 59) return 1;
    if (score <= 84) return 2;
    return 3;
  }

  function schemeClass(scheme) {
    if (!scheme) return null;
    return PQ_SCHEMES.indexOf(String(scheme)) !== -1 ? 'pq' : 'classical';
  }

  function fmtDuration(sec) {
    sec = Math.max(0, Math.floor(Number(sec) || 0));
    if (sec >= 86400 && sec % 3600 === 0) {
      const d = Math.floor(sec / 86400), h = (sec % 86400) / 3600;
      return d + 'd' + (h ? ' ' + h + 'h' : '');
    }
    if (sec >= 3600) {
      const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
      return h + 'h' + (m ? ' ' + m + 'm' : '');
    }
    if (sec >= 60) {
      const m = Math.floor(sec / 60), s = sec % 60;
      return m + 'm' + (s ? ' ' + s + 's' : '');
    }
    return sec + 's';
  }

  function fmtUnits(raw, decimals) {
    if (raw === null || raw === undefined) return '-';
    const neg = raw < 0n;
    let v = neg ? -raw : raw;
    const base = 10n ** BigInt(decimals);
    const whole = v / base;
    let frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '');
    return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '');
  }

  /*
   * Preflight of PayGuardSim.createEscrow, same branch order, stopping at the
   * first failure. Hash and commitment checks are left out because the page
   * computes both itself, and the recipient check because the page only
   * offers valid recipients. Allowance and balance run last, as in the
   * simulator, when the caller passes them: a later session's approve()
   * replaces the payer's allowance, so an earlier session can run short.
   */
  function preflight(p) {
    const checks = [];
    let firstFail = null;
    const add = (name, ok, code, detail) => {
      if (firstFail) { checks.push({ name, state: 'skipped', code, detail: detail || '' }); return; }
      checks.push({ name, state: ok ? 'pass' : 'fail', code, detail: detail || '' });
      if (!ok) firstFail = code;
    };
    const s = p.session;
    if (!s) return { checks: [], firstFail: 'NoSession' };
    const dead = s.revoked ? 'SessionRevokedErr'
      : (s.paused ? 'SessionPausedErr' : (p.now >= s.expiry ? 'SessionExpiredErr' : null));
    add('session live', !dead, dead || 'SessionRevokedErr');
    const actor = String(p.actor || '').toLowerCase();
    add('actor is payer or operator',
      actor === String(s.payer).toLowerCase() || (s.operator !== ZERO && actor === String(s.operator).toLowerCase()),
      'NotSessionActor');
    const amt = p.amountRaw;
    add('amount positive', amt !== null && amt > 0n, 'InvalidAmount');
    add('amount within per tx cap', amt !== null && amt <= s.maxPerTx, 'PerTxCapExceeded',
      fmtUnits(s.maxPerTx, p.decimals) + ' cap');
    add('amount within cumulative cap', amt !== null && amt <= s.capTotal - s.spent, 'CumulativeCapExceeded',
      fmtUnits(s.capTotal - s.spent, p.decimals) + ' left');
    const sc = p.score;
    add('score in 0..100', Number.isInteger(sc) && sc >= 0 && sc <= 100, 'InvalidScore');
    add('deadline in the future', p.deadlineSecs > 0, 'InvalidDeadline');
    const tier = Number.isInteger(sc) && sc >= 0 && sc <= 100 ? tierOf(sc) : null;
    if (tier === 2) add('high tier has a guardian', s.guardian !== ZERO, 'HighTierNeedsGuardian');
    if (tier !== null && tier !== 3) {
      const delay = tier === 0 ? 0 : (tier === 1 ? s.mediumDelay : s.highDelay);
      add('deadline after unlock', p.deadlineSecs > delay, 'DeadlineBeforeUnlock',
        'unlock ' + fmtDuration(delay) + ', deadline ' + fmtDuration(p.deadlineSecs));
    }
    if (p.allowance !== undefined && p.allowance !== null) {
      add('allowance covers amount', amt !== null && amt <= p.allowance, 'InsufficientAllowance',
        fmtUnits(p.allowance, p.decimals) + ' approved');
    }
    if (p.balance !== undefined && p.balance !== null) {
      add('payer balance covers amount', amt !== null && amt <= p.balance, 'InsufficientBalance');
    }
    return { checks, firstFail };
  }

  function releasePath(tier, session) {
    if (tier === 0) return 'instant release to recipient';
    if (tier === 1) return 'timelock ' + (session ? fmtDuration(session.mediumDelay) : 'medium delay') + ', payer may revoke first';
    if (tier === 2) return 'timelock ' + (session ? fmtDuration(session.highDelay) : 'high delay') + ' plus guardian co-sign';
    return 'quarantined, payer reclaims';
  }

  const TIER_TONE = ['ok', 'warn', 'high', 'bad'];

  function attackChips(stage, attacks) {
    return Object.keys(ATTACK_STAGE).filter((id) => ATTACK_STAGE[id] === stage).map((id) => {
      const v = attacks && attacks[id];
      return {
        id, label: ATTACK_LABEL[id],
        verdict: v || 'not run',
        tone: !v ? 'idle' : (HELD.indexOf(v) !== -1 ? 'ok' : 'bad')
      };
    });
  }

  function escrowStage(e, now) {
    if (!e) {
      return { node: null, chip: { text: 'no escrow', tone: 'idle' }, line: 'Fund an escrow in the simulator to drive this stage.' };
    }
    const tierName = TIER_NAMES[e.tier];
    if (e.status === 2) return { node: 'released', chip: { text: 'released', tone: 'ok' }, line: 'escrow ' + e.id + ' paid out to the recipient' };
    if (e.status === 3) return { node: 'revoked', chip: { text: 'revoked', tone: 'warn' }, line: 'escrow ' + e.id + ' returned to the payer' };
    if (e.status !== 1) return { node: null, chip: { text: 'unknown', tone: 'idle' }, line: 'escrow ' + e.id + ' has no funded state' };
    const b = e.blocker;
    if (b === 'quarantined') return { node: 'quarantined', chip: { text: 'quarantined', tone: 'bad' }, line: 'critical tier: release is impossible, the payer revokes to reclaim' };
    if (b === 'timelock') {
      return { node: 'gate', chip: { text: 'timelock', tone: 'warn' },
        line: tierName + ' tier unlocks in ' + fmtDuration(e.releaseNotBefore - now) };
    }
    if (b === 'guardian') return { node: 'gate', chip: { text: 'awaiting guardian', tone: 'high' }, line: 'high tier: timelock elapsed, guardian co-sign still missing' };
    if (b === '') return { node: 'gate', chip: { text: 'gate open', tone: 'ok' }, line: 'every release condition holds, release is allowed now' };
    return { node: 'funded', chip: { text: 'frozen', tone: 'bad' }, line: 'release blocked: ' + b };
  }

  function receiptStage(r) {
    if (!r || !r.state || r.state === 'idle') {
      return { chip: { text: 'no receipt', tone: 'idle' }, line: 'Build and WOTS sign a receipt to drive this stage.' };
    }
    const counts = r.passed + '/' + r.total + ' checks';
    if (r.state === 'verified') {
      return { chip: { text: 'verified', tone: 'ok' },
        line: counts + (r.leaf !== null && r.leaf !== undefined ? ', signed on leaf ' + r.leaf : '') };
    }
    return { chip: { text: r.tampered ? 'tamper rejected' : 'rejected', tone: 'bad' },
      line: (r.total - r.passed) + ' of ' + r.total + ' checks failed' + (r.tampered ? ' on the tampered copy' : '') };
  }

  /*
   * input: {
   *   scheme, panelScore: { score, tierName } | null,
   *   pending: { score, source: 'panel'|'override', amountRaw, actor, deadlineSecs },
   *   session: sim session object | null, sessionId, now, decimals,
   *   escrow: { id, status, tier, riskScore, releaseNotBefore, blocker } | null,
   *   lastRevert: { reason, at } | null,
   *   attacks: { [id]: verdict }, receipt: { state, passed, total, leaf, tampered, leaves, used }
   * }
   */
  function derive(input) {
    const i = input || {};
    const decimals = i.decimals === undefined ? 6 : i.decimals;
    const pending = i.pending || {};
    const score = Number.isInteger(pending.score) ? pending.score : null;
    const tier = score !== null && score >= 0 && score <= 100 ? tierOf(score) : null;
    const cls = schemeClass(i.scheme);

    const risk = {
      score, tier, tierName: tier === null ? null : TIER_NAMES[tier],
      pct: score === null ? 0 : Math.max(0, Math.min(100, score)),
      source: pending.source || 'panel',
      scheme: i.scheme || null,
      schemeClass: cls,
      schemeChip: cls === null ? null : {
        text: cls === 'pq' ? 'PQ-resistant family' : 'quantum-vulnerable',
        tone: cls === 'pq' ? 'ok' : 'bad'
      },
      path: tier === null ? 'enter a score from 0 to 100' : releasePath(tier, i.session),
      chip: tier === null ? { text: 'invalid score', tone: 'bad' } : { text: TIER_NAMES[tier], tone: TIER_TONE[tier] },
      attacks: attackChips('risk', i.attacks)
    };

    const pf = preflight({
      session: i.session, now: i.now, actor: pending.actor, amountRaw: pending.amountRaw === undefined ? null : pending.amountRaw,
      score, deadlineSecs: pending.deadlineSecs || 0, decimals,
      allowance: i.allowance, balance: i.balance
    });
    const s = i.session;
    const cap = {
      sessionId: s ? i.sessionId : null,
      checks: pf.checks,
      firstFail: pf.firstFail,
      chip: !s ? { text: 'no session', tone: 'idle' }
        : (pf.firstFail ? { text: 'would revert', tone: 'bad' } : { text: 'clear', tone: 'ok' }),
      spentPct: s && s.capTotal > 0n ? Number((s.spent * 10000n) / s.capTotal) / 100 : 0,
      pendingPct: s && s.capTotal > 0n && pending.amountRaw && pending.amountRaw > 0n
        ? Math.min(100, Number((pending.amountRaw * 10000n) / s.capTotal) / 100) : 0,
      spent: s ? fmtUnits(s.spent, decimals) : null,
      capTotal: s ? fmtUnits(s.capTotal, decimals) : null,
      maxPerTx: s ? fmtUnits(s.maxPerTx, decimals) : null,
      lastRevert: i.lastRevert ? i.lastRevert.reason : null,
      attacks: attackChips('cap', i.attacks)
    };

    const es = escrowStage(i.escrow, i.now);
    const escrow = Object.assign({ id: i.escrow ? i.escrow.id : null, attacks: attackChips('escrow', i.attacks) }, es);

    const rs = receiptStage(i.receipt);
    const r = i.receipt || {};
    const receipt = Object.assign({
      passed: r.state && r.state !== 'idle' && Number.isInteger(r.passed) ? r.passed : 0,
      total: r.state && r.state !== 'idle' && Number.isInteger(r.total) ? r.total : 0,
      leaves: Number.isInteger(r.leaves) ? r.leaves : 0,
      used: Number.isInteger(r.used) ? r.used : 0,
      lastLeaf: Number.isInteger(r.leaf) ? r.leaf : null,
      attacks: attackChips('receipt', i.attacks)
    }, rs);

    let decision;
    if (tier === null) decision = { text: 'Next escrow: score is not valid', tone: 'bad' };
    else if (!s) decision = { text: 'Next escrow: ' + TIER_NAMES[tier] + ' tier, needs a session policy first', tone: 'idle' };
    else if (pf.firstFail) decision = { text: 'Next escrow: reverts with ' + pf.firstFail, tone: 'bad' };
    else if (tier === 0) decision = { text: 'Next escrow: releases instantly', tone: 'ok' };
    else if (tier === 1) decision = { text: 'Next escrow: timelocked ' + fmtDuration(s.mediumDelay), tone: 'warn' };
    else if (tier === 2) decision = { text: 'Next escrow: timelocked ' + fmtDuration(s.highDelay) + ' plus guardian co-sign', tone: 'high' };
    else decision = { text: 'Next escrow: quarantined, payer reclaims', tone: 'bad' };

    const all = Object.keys(ATTACK_STAGE);
    const ran = all.filter((id) => i.attacks && i.attacks[id]);
    const held = ran.filter((id) => HELD.indexOf(i.attacks[id]) !== -1);
    const defenses = { ran: ran.length, held: held.length, total: all.length };

    return { decision, defenses, stages: { risk, cap, escrow, receipt } };
  }

  // ---- DOM binding (browser only) ---------------------------------------------

  function bind() {
    if (typeof document === 'undefined') return;
    const $ = (id) => document.getElementById(id);
    if (!$('pipeline')) return;
    const P = root().PQPG;

    function esc(str) {
      return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }
    function chip(el, c) {
      if (!el || !c) return;
      el.textContent = c.text;
      el.setAttribute('data-tone', c.tone);
    }
    function atkRow(list) {
      return '<ul class="pipe-atk">' + list.map((a) =>
        '<li data-tone="' + a.tone + '"><span>' + esc(a.label) + '</span><b>' + esc(a.verdict.toLowerCase()) + '</b></li>'
      ).join('') + '</ul>';
    }

    function gather() {
      const view = P.view || {};
      const wb = P.workbench || {};
      const CH = P.chain;
      const sim = view.sim;
      const cur = view.score ? view.score() : null;
      const overrideRaw = ($('esc-score') && $('esc-score').value || '').trim();
      let pendingScore = cur ? cur.score : null;
      let source = 'panel';
      if (overrideRaw !== '') {
        pendingScore = Number(overrideRaw);
        source = 'override';
        if (!Number.isInteger(pendingScore)) pendingScore = NaN;
      }
      let amountRaw = null;
      try { amountRaw = CH.parseTokenUnits($('esc-amount').value, CH.TUSD8.decimals); } catch (e) { amountRaw = null; }
      const sid = Number(($('esc-session') && $('esc-session').value) || 0);
      const session = sim && sim.sessions.has(sid) ? sim.sessions.get(sid) : null;
      let escrow = null;
      if (sim && sim.escrows.size) {
        const id = Math.max.apply(null, [...sim.escrows.keys()]);
        const e = sim.escrows.get(id);
        escrow = { id, status: e.status, tier: e.tier, riskScore: e.riskScore, releaseNotBefore: e.releaseNotBefore,
          blocker: e.status === 1 ? sim.releaseBlocker(id) : '' };
      }
      let lastRevert = null;
      if (sim) {
        for (let k = sim.audit.length - 1; k >= 0; k--) {
          if (sim.audit[k].event === 'revert') { lastRevert = sim.audit[k]; break; }
        }
      }
      const attacks = {};
      const ar = wb.attacks || {};
      Object.keys(ar).forEach((id) => { attacks[id] = ar[id].verdict; });
      return {
        scheme: cur ? cur.scheme : ($('in-scheme') ? $('in-scheme').value : null),
        pending: {
          score: pendingScore, source, amountRaw,
          actor: $('sim-actor') ? $('sim-actor').value : '',
          deadlineSecs: Number(($('esc-deadline') && $('esc-deadline').value) || 0) * 3600
        },
        session, sessionId: sid, now: sim ? sim.now : 0, decimals: CH.TUSD8.decimals,
        allowance: session ? sim.allowance(session.payer, sim.contractAddress) : null,
        balance: session ? sim.balanceOf(session.payer) : null,
        escrow, lastRevert, attacks,
        receipt: wb.receipt ? wb.receipt() : null
      };
    }

    function render() {
      let m;
      try { m = derive(gather()); } catch (e) {
        // never leave a stale verdict on screen: say so, and surface the error to the audit hooks
        const msg = String(e && e.message || e);
        try { (window.__pqpgErrors = window.__pqpgErrors || []).push('pipeline:' + msg); } catch (e2) { /* ignore */ }
        const d = $('pipe-decision');
        if (d) { d.textContent = 'Pipeline unavailable: ' + msg; d.setAttribute('data-tone', 'bad'); }
        return;
      }
      const st = m.stages;

      const dec = $('pipe-decision');
      dec.textContent = m.decision.text;
      dec.setAttribute('data-tone', m.decision.tone);
      const def = $('pipe-defenses');
      def.textContent = m.defenses.ran === 0 ? 'attacks not run'
        : m.defenses.held + '/' + m.defenses.total + ' defenses held' + (m.defenses.ran < m.defenses.total ? ' (' + m.defenses.ran + ' run)' : '');
      def.setAttribute('data-tone', m.defenses.ran === 0 ? 'idle' : (m.defenses.held === m.defenses.ran ? 'ok' : 'bad'));

      // 1. risk
      chip($('pipe-risk-chip'), st.risk.chip);
      const r = st.risk;
      $('pipe-risk').innerHTML =
        '<div class="readout"><span class="readout-num">' + (r.score === null ? '-' : r.score) + '</span>' +
        '<span class="readout-unit">/ 100 ' + (r.source === 'override' ? 'escrow form override' : 'score panel') + '</span></div>' +
        '<div class="meter" role="img" aria-label="risk score ' + esc(r.score === null ? 'invalid' : r.score) + ' of 100, ' + esc(r.tierName || 'invalid') + ' tier">' +
        '<span class="meter-zone z0"></span><span class="meter-zone z1"></span><span class="meter-zone z2"></span><span class="meter-zone z3"></span>' +
        (r.score === null ? '' : '<span class="meter-needle" style="left:' + r.pct + '%"></span>') +
        '</div>' +
        '<div class="meter-scale" aria-hidden="true"><span>0</span><span style="left:30%">30</span><span style="left:60%">60</span><span style="left:85%">85</span><span style="left:100%">100</span></div>' +
        (r.schemeChip ? '<div class="scheme-row">' + (r.source === 'override' ? '<span class="readout-unit">score panel scheme</span>' : '') + '<code>' + esc(r.scheme) + '</code><span class="pchip" data-tone="' + r.schemeChip.tone + '">' + esc(r.schemeChip.text) + '</span></div>' : '') +
        '<p class="stage-line">' + esc(r.path) + '</p>' + atkRow(r.attacks);

      // 2. cap gate
      chip($('pipe-cap-chip'), st.cap.chip);
      const c = st.cap;
      let capHtml;
      if (c.sessionId === null) {
        capHtml = '<p class="stage-line">Create a session policy in the simulator to arm this gate.</p>';
      } else {
        capHtml =
          '<div class="readout"><span class="readout-num sm">' + esc(c.spent) + '</span><span class="readout-unit">/ ' + esc(c.capTotal) + ' tUSD8 spent</span></div>' +
          '<div class="capbar" role="img" aria-label="cumulative spend ' + c.spentPct + ' percent of cap">' +
          '<span class="capbar-spent" style="width:' + Math.min(100, c.spentPct) + '%"></span>' +
          '<span class="capbar-next" style="left:' + Math.min(100, c.spentPct) + '%;width:' + Math.max(0, Math.min(100 - c.spentPct, c.pendingPct)) + '%"></span>' +
          '</div>' +
          '<p class="leaf-cap">session ' + c.sessionId + ' cumulative spend, hatched segment is the next escrow</p>' +
          '<ul class="gate-checks">' + c.checks.map((k) =>
            '<li data-state="' + k.state + '"><span class="gc-mark" aria-hidden="true">' + (k.state === 'pass' ? '\u2713' : (k.state === 'fail' ? '\u2715' : '\u00b7')) + '</span>' +
            '<span class="gc-name">' + esc(k.name) + (k.state === 'fail' ? ' <code>' + esc(k.code) + '</code>' : '') + '</span>' +
            (k.detail && k.state !== 'skipped' ? '<span class="gc-detail">' + esc(k.detail) + '</span>' : '') + '</li>'
          ).join('') + '</ul>';
      }
      capHtml += (c.lastRevert ? '<p class="stage-line">last simulator revert <code>' + esc(c.lastRevert) + '</code></p>' : '') + atkRow(c.attacks);
      $('pipe-cap').innerHTML = capHtml;

      // 3. escrow state machine
      chip($('pipe-escrow-chip'), st.escrow.chip);
      const e = st.escrow;
      const node = (key, label) => '<span class="fsm-node" data-node="' + key + '"' + (e.node === key ? ' data-active="true"' : '') + '>' + label + '</span>';
      $('pipe-escrow').innerHTML =
        '<div class="readout"><span class="readout-num sm">' + (e.id === null ? '-' : 'escrow ' + e.id) + '</span></div>' +
        '<div class="fsm" data-tone="' + e.chip.tone + '" role="img" aria-label="escrow state ' + esc(e.chip.text) + '">' +
        '<div class="fsm-row">' + node('funded', 'funded') + '<span class="fsm-arrow" aria-hidden="true"></span>' + node('gate', 'gate') + '<span class="fsm-arrow" aria-hidden="true"></span>' + node('released', 'released') + '</div>' +
        '<div class="fsm-row fsm-exits">' + node('revoked', 'revoked') + node('quarantined', 'quarantined') + '</div>' +
        '</div>' +
        '<p class="stage-line">' + esc(e.line) + '</p>' + atkRow(e.attacks);

      // 4. receipt verifier
      chip($('pipe-receipt-chip'), st.receipt.chip);
      const rc = st.receipt;
      let leafHtml = '';
      if (rc.leaves > 0) {
        leafHtml = '<div class="leafmap" role="img" aria-label="' + rc.used + ' of ' + rc.leaves + ' one time leaves used">';
        for (let k = 0; k < rc.leaves; k++) {
          leafHtml += '<span' + (k < rc.used ? ' data-used="true"' : '') + (k === rc.lastLeaf ? ' data-last="true"' : '') + '></span>';
        }
        leafHtml += '</div><p class="leaf-cap">' + rc.used + ' of ' + rc.leaves + ' one time leaves used</p>';
      }
      $('pipe-receipt').innerHTML =
        '<div class="readout"><span class="readout-num sm">' + (rc.total ? rc.passed + '/' + rc.total : '-') + '</span>' +
        '<span class="readout-unit">' + (rc.total ? 'receipt checks pass' : 'no receipt checked yet') + '</span></div>' + leafHtml +
        '<p class="stage-line">' + esc(rc.line) + '</p>' + atkRow(rc.attacks);

      const live = $('pipeline');
      live.setAttribute('data-risk', st.risk.tierName || 'invalid');
      live.setAttribute('data-cap', st.cap.chip.tone);
      live.setAttribute('data-escrow', st.escrow.node || 'none');
      live.setAttribute('data-receipt', st.receipt.chip.tone);
    }

    document.addEventListener('pqpg:update', render);
    ['esc-score', 'esc-amount', 'esc-session', 'esc-deadline', 'sim-actor'].forEach((id) => {
      const el = $(id);
      if (el) { el.addEventListener('input', render); el.addEventListener('change', render); }
    });
    render();
  }

  function root() {
    return typeof globalThis !== 'undefined' ? globalThis : window;
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
    else bind();
  }

  return { derive, preflight, tierOf, schemeClass, fmtDuration, PQ_SCHEMES, ATTACK_STAGE };
}));
