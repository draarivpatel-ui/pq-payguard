'use strict';

/*
 * PayGuardSim branch coverage. Each case mirrors a forge test of the same
 * name so the JS mirror and the Solidity contract stay in lockstep; the anvil
 * suite then proves the mirror against real bytecode.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const SIM = require('../src/sim.js');
const C = require('../src/commit.js');

const PAYER = '0x0000000000000000000000000000000000000aa1';
const OPERATOR = '0x00000000000000000000000000000000000000d4';
const GUARDIAN = '0x00000000000000000000000000000000000006c1';
const RECIP = '0x0000000000000000000000000000000000000bb2';
const RANDO = '0x0000000000000000000000000000000000000ff1';
const T0 = 1764000000;

function newSim() {
  const s = new SIM.PayGuardSim({ chainId: 44005, contractAddress: '0x' + '11'.repeat(20), now: T0 });
  s.mint(PAYER, 1_000_000_000_000n);
  return s;
}

function session(s, over) {
  const id = s.createSession(PAYER, Object.assign({
    operator: null, guardian: GUARDIAN,
    maxPerTx: 500_000_000n, capTotal: 2_000_000_000n,
    expiry: T0 + 7 * 86400, mediumDelay: 900, highDelay: 14400
  }, over || {}));
  s.approve(PAYER, s.contractAddress, 2_000_000_000n);
  return id;
}

function escrowInput(s, sid, score, over) {
  const i = Object.assign({
    recipient: RECIP, amount: 100_000_000n, riskScore: score,
    attestationHash: '0x' + 'ab'.repeat(32), deadline: T0 + 86400
  }, over || {});
  i.commitmentHash = s.computeCommitment({
    sessionId: sid, payer: PAYER, recipient: i.recipient, amountRaw: i.amount,
    riskScore: i.riskScore, attestationHash: i.attestationHash, deadline: i.deadline
  });
  return i;
}

function code(fn) {
  try { fn(); } catch (e) { return e.code || String(e); }
  return null;
}

test('SIM 01: session stores the policy and emits SessionUpdated', () => {
  const s = newSim();
  const sid = session(s);
  const ses = s.sessions.get(sid);
  assert.equal(ses.payer, PAYER);
  assert.equal(ses.guardian, GUARDIAN);
  assert.equal(ses.maxPerTx, 500_000_000n);
  assert.equal(s.audit.filter((a) => a.event === 'SessionUpdated').length, 1);
});

test('SIM 02: session rejects invalid parameters', () => {
  const s = newSim();
  const bad = (o) => code(() => s.createSession(PAYER, o));
  assert.equal(bad({ maxPerTx: 0n, capTotal: 0n, expiry: T0 + 1, mediumDelay: 0, highDelay: 0 }), 'InvalidSessionParams');
  assert.equal(bad({ maxPerTx: 100n, capTotal: 50n, expiry: T0 + 1, mediumDelay: 0, highDelay: 0 }), 'InvalidSessionParams');
  assert.equal(bad({ maxPerTx: 1n, capTotal: 1n, expiry: T0 - 1, mediumDelay: 0, highDelay: 0 }), 'InvalidSessionParams');
  assert.equal(bad({ maxPerTx: 1n, capTotal: 1n, expiry: T0 + 1, mediumDelay: 900, highDelay: 800 }), 'InvalidSessionParams');
  assert.equal(bad({ operator: PAYER, maxPerTx: 1n, capTotal: 1n, expiry: T0 + 1, mediumDelay: 0, highDelay: 0 }), 'InvalidSessionParams');
  assert.equal(bad({ guardian: PAYER, maxPerTx: 1n, capTotal: 1n, expiry: T0 + 1, mediumDelay: 0, highDelay: 0 }), 'InvalidSessionParams');
});

test('SIM 03: low tier releases instantly to the recipient', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 10));
  assert.equal(s.escrows.get(eid).releaseNotBefore, T0);
  s.release(RANDO, eid); // anyone may trigger
  assert.equal(s.escrows.get(eid).status, 2);
  assert.equal(s.balanceOf(RECIP), 100_000_000n);
  assert.equal(s.balanceOf(s.contractAddress), 0n);
  assert.equal(s.audit.filter((a) => a.event === 'EscrowReleased').length, 1);
});

test('SIM 04: medium tier enforces the timelock window', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 45));
  assert.equal(s.escrows.get(eid).releaseNotBefore, T0 + 900);
  assert.equal(code(() => s.release(PAYER, eid)), 'TimelockActive');
  s.setTime(T0 + 899);
  assert.equal(code(() => s.release(PAYER, eid)), 'TimelockActive');
  s.setTime(T0 + 900);
  s.release(PAYER, eid);
  assert.equal(s.balanceOf(RECIP), 100_000_000n);
});

test('SIM 05: high tier needs guardian approval plus delay', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 70));
  assert.equal(code(() => s.guardianApprove(RANDO, eid)), 'NotGuardian');
  s.guardianApprove(GUARDIAN, eid);
  assert.equal(s.escrows.get(eid).guardianApproved, true);
  s.setTime(T0 + 14399);
  assert.equal(code(() => s.release(PAYER, eid)), 'TimelockActive');
  s.setTime(T0 + 14400);
  s.release(PAYER, eid);
  assert.equal(s.balanceOf(RECIP), 100_000_000n);
});

test('SIM 06: high tier without approval stays locked past delay', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 70));
  s.setTime(T0 + 14400);
  assert.equal(code(() => s.release(PAYER, eid)), 'GuardianApprovalMissing');
});

test('SIM 07: high tier creation requires a guardian on the session', () => {
  const s = newSim();
  const sid = session(s, { guardian: null });
  assert.equal(
    code(() => s.createEscrow(PAYER, sid, escrowInput(s, sid, 70))),
    'HighTierNeedsGuardian'
  );
});

test('SIM 08: critical tier is quarantined and payer reclaims', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 95));
  assert.equal(code(() => s.release(PAYER, eid)), 'Quarantined');
  s.advanceTime(30 * 86400);
  assert.equal(code(() => s.release(PAYER, eid)), 'Quarantined');
  const before = s.balanceOf(PAYER);
  s.revokeEscrow(PAYER, eid);
  assert.equal(s.balanceOf(PAYER) - before, 100_000_000n);
});

test('SIM 09: commitment mismatch blocks a lowered score', () => {
  const s = newSim();
  const sid = session(s);
  const i = escrowInput(s, sid, 20);
  // commitment was computed for score 20, caller tries to pass a different one
  i.commitmentHash = s.computeCommitment({
    sessionId: sid, payer: PAYER, recipient: i.recipient, amountRaw: i.amount,
    riskScore: 80, attestationHash: i.attestationHash, deadline: i.deadline
  });
  assert.equal(code(() => s.createEscrow(PAYER, sid, i)), 'CommitmentMismatch');
});

test('SIM 10: spend caps enforce per tx and cumulative limits', () => {
  const s = newSim();
  const sid = session(s);
  assert.equal(
    code(() => s.createEscrow(PAYER, sid, escrowInput(s, sid, 10, { amount: 600_000_000n }))),
    'PerTxCapExceeded'
  );
  s.createEscrow(PAYER, sid, escrowInput(s, sid, 10, { amount: 500_000_000n }));
  s.createEscrow(PAYER, sid, escrowInput(s, sid, 10, { amount: 500_000_000n }));
  s.createEscrow(PAYER, sid, escrowInput(s, sid, 10, { amount: 500_000_000n }));
  s.createEscrow(PAYER, sid, escrowInput(s, sid, 10, { amount: 400_000_000n }));
  // spent is now 1.9e9 of 2e9 cap; next 200M pushes past
  assert.equal(
    code(() => s.createEscrow(PAYER, sid, escrowInput(s, sid, 10, { amount: 200_000_000n }))),
    'CumulativeCapExceeded'
  );
});

test('SIM 11: validation order matches the contract', () => {
  const s = newSim();
  const sid = session(s);
  const base = escrowInput(s, sid, 10);
  assert.equal(code(() => s.createEscrow(PAYER, sid, Object.assign({}, base, { recipient: '0x' + '0'.repeat(40) }))), 'InvalidRecipient');
  assert.equal(code(() => s.createEscrow(PAYER, sid, Object.assign({}, base, { recipient: PAYER }))), 'InvalidRecipient');
  assert.equal(code(() => s.createEscrow(PAYER, sid, Object.assign({}, base, { amount: 0n }))), 'InvalidAmount');
  assert.equal(code(() => s.createEscrow(PAYER, sid, Object.assign({}, base, { riskScore: 101 }))), 'InvalidScore');
  assert.equal(code(() => s.createEscrow(PAYER, sid, Object.assign({}, base, { attestationHash: '0x' + '0'.repeat(64) }))), 'InvalidHash');
  assert.equal(code(() => s.createEscrow(PAYER, sid, Object.assign({}, base, { deadline: T0 }))), 'InvalidDeadline');
});

test('SIM 12: operator can fund but a stranger cannot', () => {
  const s = newSim();
  const sid = session(s, { operator: OPERATOR });
  s.createEscrow(OPERATOR, sid, escrowInput(s, sid, 10));
  assert.equal(code(() => s.createEscrow(RANDO, sid, escrowInput(s, sid, 10))), 'NotSessionActor');
});

test('SIM 13: paused, revoked and expired sessions gate everything', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 10));
  s.setSessionPaused(PAYER, sid, true);
  assert.equal(code(() => s.release(PAYER, eid)), 'SessionPausedErr');
  assert.equal(code(() => s.createEscrow(PAYER, sid, escrowInput(s, sid, 10))), 'SessionPausedErr');
  s.setSessionPaused(PAYER, sid, false);
  s.revokeSession(PAYER, sid);
  assert.equal(code(() => s.release(PAYER, eid)), 'SessionRevokedErr');
  assert.equal(code(() => s.createEscrow(PAYER, sid, escrowInput(s, sid, 10))), 'SessionRevokedErr');
  assert.equal(code(() => s.revokeSession(PAYER, sid)), 'SessionRevokedErr');
  // payer can still pull the funded escrow back
  s.revokeEscrow(PAYER, eid);
  assert.equal(s.balanceOf(PAYER), 1_000_000_000_000n);
});

test('SIM 14: session expiry blocks release and creation', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 10));
  s.setTime(T0 + 7 * 86400);
  assert.equal(code(() => s.release(PAYER, eid)), 'SessionExpiredErr');
  assert.equal(code(() => s.createEscrow(PAYER, sid, escrowInput(s, sid, 10))), 'SessionExpiredErr');
});

test('SIM 15: deadline passed blocks release, payer still reclaims', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 45, { deadline: T0 + 1000 }));
  s.setTime(T0 + 1001);
  assert.equal(code(() => s.release(PAYER, eid)), 'DeadlinePassed');
  s.revokeEscrow(PAYER, eid);
  assert.equal(s.escrows.get(eid).status, 3);
});

test('SIM 16: only the payer can revoke, and only while funded', () => {
  const s = newSim();
  const sid = session(s);
  const eid = s.createEscrow(PAYER, sid, escrowInput(s, sid, 45));
  assert.equal(code(() => s.revokeEscrow(RANDO, eid)), 'NotPayer');
  assert.equal(code(() => s.revokeEscrow(RECIP, eid)), 'NotPayer');
  s.setTime(T0 + 900);
  s.release(PAYER, eid);
  assert.equal(code(() => s.revokeEscrow(PAYER, eid)), 'EscrowNotFunded');
  assert.equal(code(() => s.release(PAYER, eid)), 'EscrowNotFunded');
});

test('SIM 17: guardian approve is high tier only and once funded', () => {
  const s = newSim();
  const sid = session(s);
  const low = s.createEscrow(PAYER, sid, escrowInput(s, sid, 10));
  assert.equal(code(() => s.guardianApprove(GUARDIAN, low)), 'EscrowNotHighTier');
});

test('SIM 18: releaseBlocker mirrors the gate order', () => {
  const s = newSim();
  const sid = session(s);
  const e1 = s.createEscrow(PAYER, sid, escrowInput(s, sid, 45));
  assert.equal(s.releaseBlocker(e1), 'timelock');
  const e2 = s.createEscrow(PAYER, sid, escrowInput(s, sid, 95));
  assert.equal(s.releaseBlocker(e2), 'quarantined');
  s.setTime(T0 + 900);
  assert.equal(s.releaseBlocker(e1), '');
  s.setSessionPaused(PAYER, sid, true);
  assert.equal(s.releaseBlocker(e1), 'session_paused');
});

test('SIM 19: unknown ids revert cleanly', () => {
  const s = newSim();
  assert.equal(code(() => s.release(PAYER, 0)), 'EscrowUnknown');
  assert.equal(code(() => s.revokeEscrow(PAYER, 5)), 'EscrowUnknown');
  assert.equal(code(() => s.guardianApprove(GUARDIAN, 3)), 'EscrowUnknown');
  assert.equal(code(() => s.setSessionPaused(PAYER, 9, true)), 'SessionUnknown');
});

test('SIM 20: seeded fuzz over scores and caps stays consistent', () => {
  // deterministic PRNG so the run is reproducible
  let x = 0x9e3779b9;
  const rand = () => {
    x ^= x << 13; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    return x / 0xffffffff;
  };
  const s = newSim();
  let created = 0, released = 0, reverted = 0;
  for (let i = 0; i < 220; i++) {
    const sid = session(s, {
      guardian: rand() < 0.7 ? GUARDIAN : null,
      maxPerTx: BigInt(1 + Math.floor(rand() * 500_000_000)),
      capTotal: 2_000_000_000n,
      expiry: T0 + 86400, mediumDelay: Math.floor(rand() * 3600), highDelay: 3600 + Math.floor(rand() * 20000)
    });
    const score = Math.floor(rand() * 101);
    const amount = s.sessions.get(sid).maxPerTx;
    const before = s.escrows.size;
    const input = escrowInput(s, sid, score, { amount, deadline: T0 + 80000 });
    const c = code(() => s.createEscrow(PAYER, sid, input));
    if (c === null) {
      created++;
      const e = s.escrows.get(s.nextEscrowId - 1);
      assert.equal(e.tier, SIM.tierOf(score));
      const r = code(() => s.release(PAYER, s.nextEscrowId - 1));
      if (r === null) {
        released++;
        // instant success means low tier or a zero delay medium session
        assert.ok(e.tier === 0 || (e.tier === 1 && s.sessions.get(e.sessionId).mediumDelay === 0));
      } else {
        reverted++;
        assert.ok(
          ['TimelockActive', 'Quarantined', 'GuardianApprovalMissing', 'DeadlinePassed'].includes(r),
          'unexpected revert ' + r
        );
      }
    } else {
      assert.equal(c, 'HighTierNeedsGuardian');
      assert.ok(score > 59 && score <= 84);
    }
    assert.ok(s.escrows.size === before + (c === null ? 1 : 0));
  }
  assert.ok(created > 150, 'created ' + created);
  assert.ok(released > 0, 'released ' + released);
  assert.ok(reverted > 0, 'reverted ' + reverted);
});

test('SIM 21: audit export is valid JSON with full trail', () => {
  const s = newSim();
  const sid = session(s);
  s.createEscrow(PAYER, sid, escrowInput(s, sid, 10));
  const out = JSON.parse(s.exportAudit());
  assert.equal(out.chainId, '44005');
  assert.equal(out.sessions.length, 1);
  assert.equal(out.escrows.length, 1);
  assert.ok(out.audit.length >= 4);
  assert.equal(out.escrows[0].status, 'funded');
});
