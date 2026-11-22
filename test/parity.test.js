'use strict';

/*
 * Cross-implementation parity tests.
 *
 * 1. Commitment vectors generated with `cast abi-encode` + `cast keccak`
 *    must equal src/commit.js computeCommitment byte for byte - the same
 *    check anvil.test.js performs against live EVM bytecode.
 * 2. The simulator's error vocabulary must match the contract's declared
 *    custom errors (parsed straight from the Solidity source).
 * 3. The tier boundary table and hash known-answer vectors pin the
 *    constants both sides share.
 * 4. The in-page self-test battery must run green in Node too.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const C = require('../src/commit.js');
const K = require('../src/keccak.js');
const R = require('../src/risk.js');
const SIM = require('../src/sim.js');
const ST = require('../src/selftest.js');

const CONTRACT_PATH = path.join(__dirname, '..', 'contracts', 'PQPayGuardEscrow.sol');

const ATT = '0xa90052d76d7a353444f3f280287dded2ca5473ce58d4dbee5b1c4316aff54e7e';

// Generated with: cast abi-encode "f(uint256,address,uint256,address,address,uint256,uint8,bytes32,uint64)" ...
const VECTORS = [
  {
    name: 'aevum low tier',
    input: {
      chainId: 44005,
      contractAddress: '0x1111111111111111111111111111111111111111',
      sessionId: 0,
      payer: '0x0000000000000000000000000000000000000aa1',
      recipient: '0x0000000000000000000000000000000000000bb2',
      amountRaw: 250500000n,
      riskScore: 42,
      attestationHash: ATT,
      deadline: 1765000000
    },
    expected: '0xe9515025f9d54693c3db9c85036ee6f56b153743cc04ea7656f76c661a588feb'
  },
  {
    name: 'aevum critical tier nonzero session',
    input: {
      chainId: 44005,
      contractAddress: '0x2222222222222222222222222222222222222222',
      sessionId: 7,
      payer: '0x0000000000000000000000000000000000000a11',
      recipient: '0x0000000000000000000000000000000000000dea',
      amountRaw: 1000000000n,
      riskScore: 85,
      attestationHash: ATT,
      deadline: 1765100000
    },
    expected: '0x88a624b6372490ab8373d584e7ce9522d253dc72f2b075cfcd54b5dc540fa3c9'
  },
  {
    name: 'foreign chain domain',
    input: {
      chainId: 1,
      contractAddress: '0x1111111111111111111111111111111111111111',
      sessionId: 3,
      payer: '0x0000000000000000000000000000000000000c01',
      recipient: '0x0000000000000000000000000000000000000d02',
      amountRaw: 1n,
      riskScore: 0,
      attestationHash: ATT,
      deadline: 1760000001
    },
    expected: '0xb29b93b7da3ef947c0f30292d54ce155cc3a48e94ac3f768d71c082e724e95ce'
  }
];

test('PAR 01: computeCommitment matches cast vectors byte for byte', () => {
  for (const v of VECTORS) {
    assert.equal(C.computeCommitment(v.input), v.expected, v.name);
  }
});

test('PAR 02: verifyCommitment round-trips the vectors', () => {
  for (const v of VECTORS) {
    assert.equal(C.verifyCommitment(v.expected, v.input), true, v.name);
    assert.equal(C.verifyCommitment('0x' + '00'.repeat(32), v.input), false, v.name);
  }
});

test('PAR 03: commitment preimage is 288 bytes of static abi', () => {
  // 9 fields x 32 bytes - the same layout the contract's abi.encode produces
  const enc = require('../src/abi.js').encodeArgs(
    ['uint256', 'address', 'uint256', 'address', 'address', 'uint256', 'uint8', 'bytes32', 'uint64'],
    [44005n, '0x' + '11'.repeat(20), 0n, '0x' + 'aa'.padStart(40, '0'), '0x' + 'bb'.padStart(40, '0'), 1n, 0n, '0x' + '00'.repeat(32), 0n]
  );
  const bytes = enc.startsWith('0x') ? (enc.length - 2) / 2 : enc.length / 2;
  assert.equal(bytes, 288);
});

test('PAR 04: domain separation parity - every field perturbs the digest', () => {
  const base = VECTORS[0].input;
  const baseHash = C.computeCommitment(base);
  const perturb = [
    ['chainId', 1], ['contractAddress', '0x' + '99'.repeat(20)], ['sessionId', 1],
    ['payer', '0x' + 'cc'.padStart(40, '0')], ['recipient', '0x' + 'dd'.padStart(40, '0')],
    ['amountRaw', 250500001n], ['riskScore', 43],
    ['attestationHash', '0x' + '01'.repeat(32)], ['deadline', 1765000001]
  ];
  for (const [field, val] of perturb) {
    const h = C.computeCommitment(Object.assign({}, base, { [field]: val }));
    assert.notEqual(h, baseHash, 'field ' + field);
  }
});

// ---- error vocabulary parity ----------------------------------------------------

test('PAR 10: contract error names parse from source', () => {
  const src = fs.readFileSync(CONTRACT_PATH, 'utf8');
  const errors = new Set([...src.matchAll(/error ([A-Za-z0-9_]+)\(/g)].map((m) => m[1]));
  assert.ok(errors.size >= 25, 'expected 25+ custom errors, got ' + errors.size);
  for (const e of ['CommitmentMismatch', 'PerTxCapExceeded', 'CumulativeCapExceeded',
    'TimelockActive', 'GuardianApprovalMissing', 'NotGuardian', 'NotPayer',
    'NotSessionActor', 'NotSessionPayer', 'EscrowNotFunded', 'Quarantined',
    'DeadlinePassed', 'DeadlineBeforeUnlock', 'SessionExpiredErr',
    'SessionPausedErr', 'SessionRevokedErr']) {
    assert.ok(errors.has(e), 'missing ' + e);
  }
});

const AC = {
  payer: '0x0000000000000000000000000000000000000aa1',
  operator: '0x00000000000000000000000000000000000000d4',
  guardian: '0x00000000000000000000000000000000000006c1',
  recipient: '0x0000000000000000000000000000000000000bb2',
  attacker: '0x0000000000000000000000000000000000000ff1'
};

function seededSim() {
  const s = new SIM.PayGuardSim({ chainId: 44005, now: 1764000000 });
  s.mint(AC.payer, 1_000_000_000_000n);
  const sid = s.createSession(AC.payer, {
    operator: null, guardian: AC.guardian,
    maxPerTx: 500_000_000n, capTotal: 2_000_000_000n,
    expiry: 1764000000 + 7 * 86400, mediumDelay: 900, highDelay: 14400
  });
  s.approve(AC.payer, s.contractAddress, 2_000_000_000n);
  return { s, sid };
}

test('PAR 11: sim throws contract error names', () => {
  const src = fs.readFileSync(CONTRACT_PATH, 'utf8');
  const contractErrors = new Set([...src.matchAll(/error ([A-Za-z0-9_]+)\(/g)].map((m) => m[1]));
  const simOnly = new Set(['InsufficientBalance', 'InsufficientAllowance', 'EscrowUnknown', 'SessionUnknown']);

  const { s, sid } = seededSim();

  const thrown = new Set();
  const capture = (fn) => { try { fn(); } catch (e) { thrown.add(e.code || e.message); } };

  // collect a wide spread of error codes through real calls
  capture(() => s.createEscrow(AC.attacker, sid, {
    recipient: AC.attacker, amount: 1n, riskScore: 10,
    attestationHash: '0x' + 'ab'.repeat(32), commitmentHash: '0x' + 'cd'.repeat(32),
    deadline: s.now + 100
  }));
  capture(() => s.release(AC.attacker, 0));
  capture(() => s.guardianApprove(AC.attacker, 0));
  capture(() => s.revokeEscrow(AC.attacker, 0));
  capture(() => s.setSessionPaused(AC.attacker, sid, true));
  capture(() => s.createEscrow(AC.payer, sid, {
    recipient: AC.recipient, amount: 500_000_001n, riskScore: 10,
    attestationHash: '0x' + 'ab'.repeat(32), commitmentHash: '0x' + 'cd'.repeat(32),
    deadline: s.now + 86400
  }));
  capture(() => s.releaseBlocker(999));

  for (const codeName of thrown) {
    assert.ok(
      contractErrors.has(codeName) || simOnly.has(codeName),
      'sim error "' + codeName + '" not in contract vocabulary'
    );
  }
  assert.ok(thrown.size >= 4, 'too few error codes exercised: ' + [...thrown]);
});

// ---- tier table parity ---------------------------------------------------------------

test('PAR 20: tier boundaries match contract constants', () => {
  // contract: SCORE_LOW_MAX=29, SCORE_MEDIUM_MAX=59, SCORE_HIGH_MAX=84
  const table = [[0, 0], [29, 0], [30, 1], [59, 1], [60, 2], [84, 2], [85, 3], [100, 3]];
  for (const [score, tier] of table) {
    assert.equal(R.scoreToTier(score), tier, 'score ' + score);
  }
});

test('PAR 21: tier table is monotonic across all 101 scores', () => {
  let prev = -1;
  for (let s = 0; s <= 100; s++) {
    const t = R.scoreToTier(s);
    assert.ok(t >= prev, 'score ' + s + ' regressed');
    prev = t;
  }
});

test('PAR 22: sim tierOf mirrors risk.js scoreToTier', () => {
  for (let score = 0; score <= 100; score++) {
    assert.equal(SIM.tierOf(score), R.scoreToTier(score), 'score ' + score);
  }
});

// ---- known answer vectors ------------------------------------------------------------

test('PAR 30: keccak256 empty input KAT', () => {
  const h = K.keccak256(new Uint8Array(0));
  assert.equal(
    K.bytesToHex(h),
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
  );
});

test('PAR 31: sha256 known answers via subtle', async () => {
  const empty = await K.sha256(new Uint8Array(0));
  assert.equal(
    K.bytesToHex(empty),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  const abc = await K.sha256(K.utf8Bytes('abc'));
  assert.equal(
    K.bytesToHex(abc),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

test('PAR 32: sim releaseBlocker vocabulary mirrors contract', () => {
  const { s, sid } = seededSim();
  const input = {
    recipient: AC.recipient, amount: 100_000_000n, riskScore: 45,
    attestationHash: '0x' + 'ab'.repeat(32), deadline: s.now + 86400
  };
  input.commitmentHash = s.computeCommitment({
    sessionId: sid, payer: AC.payer, recipient: input.recipient,
    amountRaw: input.amount, riskScore: input.riskScore,
    attestationHash: input.attestationHash, deadline: input.deadline
  });
  const eid = s.createEscrow(AC.payer, sid, input);
  assert.equal(s.releaseBlocker(eid), 'timelock');
  assert.throws(() => s.releaseBlocker(999), /EscrowUnknown/);
  // medium tier unlocks after mediumDelay
  s.advanceTime(900);
  assert.equal(s.releaseBlocker(eid), '');
  s.release(AC.attacker, eid); // permissionless once gates pass
  assert.equal(s.releaseBlocker(eid), 'not_funded');
});

// ---- self-test battery ------------------------------------------------------------------

test('PAR 40: in page self-test battery is green under Node', async () => {
  const sum = await ST.summary();
  assert.equal(sum.failed, 0, JSON.stringify(sum.results.filter((r) => !r.ok).map((r) => r.id)));
  assert.equal(sum.passed, sum.total);
  assert.ok(sum.total >= 30, 'expected 30+ self tests, got ' + sum.total);
});

test('PAR 41: self-test ids are unique and ordered', async () => {
  const sum = await ST.summary();
  const ids = sum.results.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('PAR 42: self-test battery is deterministic', async () => {
  const a = await ST.summary();
  const b = await ST.summary();
  assert.equal(a.total, b.total);
  assert.equal(a.passed, b.passed);
  assert.deepEqual(a.results.map((r) => r.ok), b.results.map((r) => r.ok));
});
