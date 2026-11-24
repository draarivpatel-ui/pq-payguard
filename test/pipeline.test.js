'use strict';

/*
 * Decision pipeline view model. The preflight is proven against the real
 * PayGuardSim.createEscrow over a grid of sessions, actors, amounts, scores
 * and deadlines, so the cap gate can never show a verdict the simulator
 * would not produce. The remaining cases pin the honest idle states: no
 * pre-filled passes before a session, an escrow, an attack or a receipt.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const SIM = require('../src/sim.js');
const R = require('../src/risk.js');
const P = require('../src/pipeline.js');

const PAYER = '0x0000000000000000000000000000000000000aa1';
const OPERATOR = '0x00000000000000000000000000000000000000d4';
const GUARDIAN = '0x00000000000000000000000000000000000006c1';
const RECIP = '0x0000000000000000000000000000000000000bb2';
const RANDO = '0x0000000000000000000000000000000000000ff1';
const T0 = 1764000000;
const ATT = '0x' + 'ab'.repeat(32);
const U = 1_000_000n; // one tUSD8 in raw units

function newSim(opts) {
  const o = opts || {};
  const s = new SIM.PayGuardSim({ chainId: 44005, contractAddress: '0x' + '11'.repeat(20), now: T0 });
  s.mint(PAYER, 1_000_000n * U);
  const sid = s.createSession(PAYER, {
    operator: OPERATOR,
    guardian: o.noGuardian ? null : GUARDIAN,
    maxPerTx: 500n * U, capTotal: 1200n * U,
    expiry: T0 + 86400, mediumDelay: 900, highDelay: 14400
  });
  s.approve(PAYER, s.contractAddress, 1200n * U);
  if (o.prespend) {
    for (let k = 0; k < 2; k++) {
      const dl = s.now + 3600;
      const com = s.computeCommitment({ sessionId: sid, payer: PAYER, recipient: RECIP, amountRaw: 500n * U, riskScore: 10, attestationHash: ATT, deadline: dl });
      s.createEscrow(PAYER, sid, { recipient: RECIP, amount: 500n * U, riskScore: 10, attestationHash: ATT, commitmentHash: com, deadline: dl });
    }
  }
  if (o.paused) s.setSessionPaused(PAYER, sid, true);
  if (o.revoked) s.revokeSession(PAYER, sid);
  if (o.expired) s.advanceTime(86400);
  return { s, sid };
}

function simOutcome(s, sid, actor, amount, score, hours) {
  const deadline = s.now + hours * 3600;
  try {
    const com = Number.isInteger(score) && score >= 0 && score <= 100
      ? s.computeCommitment({ sessionId: sid, payer: PAYER, recipient: RECIP, amountRaw: amount, riskScore: score, attestationHash: ATT, deadline })
      : ATT;
    s.createEscrow(actor, sid, { recipient: RECIP, amount, riskScore: score, attestationHash: ATT, commitmentHash: com, deadline });
    return null;
  } catch (e) {
    return e.code || String(e.message);
  }
}

test('PIPE 01: tierOf matches risk.scoreToTier on every score 0..100', () => {
  for (let sc = 0; sc <= 100; sc++) {
    assert.equal(P.tierOf(sc), R.scoreToTier(sc), 'score ' + sc);
  }
});

test('PIPE 02: scheme classes agree with the score model bases', () => {
  for (const [scheme, base] of Object.entries(R.SCHEME_BASE)) {
    const cls = P.schemeClass(scheme);
    if (cls === 'pq') assert.ok(base <= 10, scheme + ' classed pq with base ' + base);
    else assert.ok(base >= 45, scheme + ' classed classical with base ' + base);
  }
  assert.equal(P.schemeClass('ml-dsa-44'), 'pq');
  assert.equal(P.schemeClass('slh-dsa-128s'), 'pq');
  assert.equal(P.schemeClass('rsa-2048'), 'classical');
  assert.equal(P.schemeClass('secp256k1'), 'classical');
  assert.equal(P.schemeClass(null), null);
});

test('PIPE 03: preflight first failure equals the simulator revert across a scenario grid', () => {
  const sessions = [{}, { paused: true }, { revoked: true }, { expired: true }, { noGuardian: true }, { prespend: true }];
  const actors = [PAYER, OPERATOR, RANDO];
  const amounts = [0n, 1n * U, 500n * U, 501n * U, 300n * U];
  const scores = [10, 45, 70, 92];
  const hours = [1, 5, 24];
  let cases = 0;
  for (const so of sessions) {
    for (const actor of actors) {
      for (const amount of amounts) {
        for (const score of scores) {
          for (const h of hours) {
            const { s, sid } = newSim(so);
            const want = simOutcome(s, sid, actor, amount, score, h);
            const { s: s2, sid: sid2 } = newSim(so);
            const got = P.preflight({
              session: s2.sessions.get(sid2), now: s2.now, actor, amountRaw: amount,
              score, deadlineSecs: h * 3600, decimals: 6
            }).firstFail;
            assert.equal(got, want, JSON.stringify({ so, actor, amount: String(amount), score, h }));
            cases++;
          }
        }
      }
    }
  }
  assert.ok(cases >= 1000, 'grid too small: ' + cases);
});

test('PIPE 04: no session, no escrow, no attacks, no receipt means idle, never a pass', () => {
  const m = P.derive({
    scheme: 'secp256k1', pending: { score: 88, source: 'panel', amountRaw: 250n * U, actor: PAYER, deadlineSecs: 86400 },
    session: null, now: T0, escrow: null, attacks: {}, receipt: null
  });
  assert.equal(m.stages.cap.chip.tone, 'idle');
  assert.equal(m.stages.escrow.chip.tone, 'idle');
  assert.equal(m.stages.receipt.chip.tone, 'idle');
  assert.equal(m.stages.receipt.total, 0);
  assert.match(m.decision.text, /needs a session policy/);
  for (const st of Object.values(m.stages)) {
    for (const a of st.attacks) assert.equal(a.verdict, 'not run');
  }
  assert.deepEqual(m.defenses, { ran: 0, held: 0, total: 6 });
});

test('PIPE 05: risk stage reports tier, scheme class and release path', () => {
  const pq = P.derive({ scheme: 'ml-dsa-44', pending: { score: 8 } });
  assert.equal(pq.stages.risk.tierName, 'low');
  assert.equal(pq.stages.risk.schemeChip.text, 'PQ-resistant family');
  assert.equal(pq.stages.risk.path, 'instant release to recipient');
  const rsa = P.derive({ scheme: 'rsa-2048', pending: { score: 100 } });
  assert.equal(rsa.stages.risk.tierName, 'critical');
  assert.equal(rsa.stages.risk.schemeChip.text, 'quantum-vulnerable');
  assert.equal(rsa.stages.risk.chip.tone, 'bad');
  const bad = P.derive({ scheme: 'rsa-2048', pending: { score: NaN, source: 'override' } });
  assert.equal(bad.stages.risk.chip.text, 'invalid score');
  assert.match(bad.decision.text, /not valid/);
});

test('PIPE 06: escrow stage follows every simulator release blocker', () => {
  const base = { id: 3, tier: 1, riskScore: 45, releaseNotBefore: T0 + 900 };
  const at = (status, blocker) => P.derive({ now: T0, escrow: Object.assign({}, base, { status, blocker }) }).stages.escrow;
  assert.equal(at(1, 'timelock').chip.text, 'timelock');
  assert.match(at(1, 'timelock').line, /unlocks in 15m/);
  assert.equal(at(1, 'guardian').chip.text, 'awaiting guardian');
  assert.equal(at(1, '').chip.text, 'gate open');
  assert.equal(at(1, 'quarantined').node, 'quarantined');
  assert.equal(at(1, 'session_paused').chip.text, 'frozen');
  assert.equal(at(2, '').node, 'released');
  assert.equal(at(3, '').node, 'revoked');
});

test('PIPE 07: escrow stage matches a live simulator walk through timelock and release', () => {
  const { s, sid } = newSim();
  const dl = s.now + 86400 - 60;
  const com = s.computeCommitment({ sessionId: sid, payer: PAYER, recipient: RECIP, amountRaw: 100n * U, riskScore: 45, attestationHash: ATT, deadline: dl });
  const eid = s.createEscrow(PAYER, sid, { recipient: RECIP, amount: 100n * U, riskScore: 45, attestationHash: ATT, commitmentHash: com, deadline: dl });
  const view = () => {
    const e = s.escrows.get(eid);
    return P.derive({ now: s.now, escrow: { id: eid, status: e.status, tier: e.tier, riskScore: e.riskScore, releaseNotBefore: e.releaseNotBefore, blocker: e.status === 1 ? s.releaseBlocker(eid) : '' } }).stages.escrow;
  };
  assert.equal(view().chip.text, 'timelock');
  s.advanceTime(900);
  assert.equal(view().chip.text, 'gate open');
  s.release(RECIP, eid);
  assert.equal(view().chip.text, 'released');
});

test('PIPE 08: receipt stage separates verified, rejected and tampered', () => {
  const ok = P.derive({ receipt: { state: 'verified', passed: 4, total: 4, leaf: 0, leaves: 16, used: 1 } }).stages.receipt;
  assert.equal(ok.chip.text, 'verified');
  assert.match(ok.line, /4\/4 checks, signed on leaf 0/);
  assert.equal(ok.used, 1);
  const tam = P.derive({ receipt: { state: 'failed', passed: 2, total: 4, tampered: true } }).stages.receipt;
  assert.equal(tam.chip.text, 'tamper rejected');
  assert.equal(tam.chip.tone, 'bad');
  assert.match(tam.line, /2 of 4 checks failed on the tampered copy/);
});

test('PIPE 09: decision names the release path per tier and the revert when the gate fails', () => {
  const { s, sid } = newSim();
  const sess = s.sessions.get(sid);
  const d = (score, amount) => P.derive({
    pending: { score, amountRaw: amount, actor: PAYER, deadlineSecs: 86400 }, session: sess, now: s.now, decimals: 6
  }).decision.text;
  assert.equal(d(10, 100n * U), 'Next escrow: releases instantly');
  assert.equal(d(45, 100n * U), 'Next escrow: timelocked 15m');
  assert.equal(d(70, 100n * U), 'Next escrow: timelocked 4h plus guardian co-sign');
  assert.equal(d(92, 100n * U), 'Next escrow: quarantined, payer reclaims');
  assert.equal(d(10, 501n * U), 'Next escrow: reverts with PerTxCapExceeded');
});

test('PIPE 10: defenses count only attacks that actually ran', () => {
  const m = P.derive({ attacks: { replay: 'REJECTED', 'shor-drain': 'PROTECTED', domain: 'COMPROMISED' } });
  assert.deepEqual(m.defenses, { ran: 3, held: 2, total: 6 });
  const risk = m.stages.risk.attacks;
  assert.equal(risk.find((a) => a.id === 'domain').tone, 'bad');
  assert.equal(m.stages.cap.attacks[0].verdict, 'not run');
});

test('PIPE 11: duration formatting is exact', () => {
  assert.equal(P.fmtDuration(0), '0s');
  assert.equal(P.fmtDuration(900), '15m');
  assert.equal(P.fmtDuration(14400), '4h');
  assert.equal(P.fmtDuration(86400), '1d');
  assert.equal(P.fmtDuration(90061), '25h 1m');
});
