'use strict';

/*
 * Tests for src/attacks.js: every scenario must produce its expected
 * verdict, with real error codes and cryptographic verdicts in the steps,
 * and must be deterministic across runs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const AT = require('../src/attacks.js');

const HELD = ['REJECTED', 'BLOCKED', 'PROTECTED'];

function labels(res) {
  return res.steps.map((s) => s.label);
}

function codes(res) {
  return res.steps.map((s) => s.detail).join(' | ');
}

// ---- runner surface ----------------------------------------------------------

test('ATK 01: six named attacks are registered', () => {
  assert.equal(AT.ATTACKS.length, 6);
  assert.deepEqual(
    AT.ATTACKS.map((a) => a.id),
    ['replay', 'domain', 'leaf-reuse', 'merkle-tamper', 'shor-drain', 'limit-bypass']
  );
});

test('ATK 02: runAll executes every attack and all defenses hold', () => {
  const results = AT.runAll();
  assert.equal(results.length, 6);
  for (const r of results) {
    assert.ok(HELD.includes(r.verdict), r.id + ' verdict ' + r.verdict);
    assert.ok(r.steps.length >= 4, r.id + ' has too few steps');
    assert.ok(r.summary.length > 20);
  }
});

test('ATK 03: runById returns a result or null', () => {
  assert.equal(AT.runById('replay').id, 'replay');
  assert.equal(AT.runById('nope'), null);
  assert.equal(AT.runById(''), null);
});

test('ATK 04: attack results are deterministic', () => {
  const a = AT.runById('merkle-tamper');
  const b = AT.runById('merkle-tamper');
  assert.deepEqual(labels(a), labels(b));
  assert.equal(a.verdict, b.verdict);
  // details embed hashes; they must also be identical across runs
  assert.equal(codes(a), codes(b));
});

test('ATK 05: every step has a kind, label and detail', () => {
  for (const r of AT.runAll()) {
    for (const s of r.steps) {
      assert.ok(['setup', 'info', 'ok', 'rejected', 'blocked', 'protected', 'compromised'].includes(s.kind),
        r.id + ' bad kind ' + s.kind);
      assert.equal(typeof s.label, 'string');
      assert.equal(typeof s.detail, 'string');
    }
  }
});

// ---- 1. replay --------------------------------------------------------------

test('ATK 10: replay verdict is REJECTED', () => {
  const r = AT.runById('replay');
  assert.equal(r.verdict, 'REJECTED');
  assert.equal(r.steps.length, 5);
});

test('ATK 11: replay shows EscrowNotFunded on the release replay', () => {
  const r = AT.runById('replay');
  assert.match(codes(r), /EscrowNotFunded/);
});

test('ATK 12: replay shows NotSessionActor on the create replay', () => {
  const r = AT.runById('replay');
  assert.match(codes(r), /NotSessionActor/);
});

test('ATK 13: replay shows payer replay stays bound to the same recipient', () => {
  const r = AT.runById('replay');
  assert.match(codes(r), /funds stay locked to/);
});

test('ATK 14: replay shows OTS replay on swapped digest fails', () => {
  const r = AT.runById('replay');
  assert.match(codes(r), /merkle|invalid|leaf/i);
  assert.doesNotMatch(codes(r), /ACCEPTED/);
});

// ---- 2. domain ---------------------------------------------------------------

test('ATK 20: domain verdict is REJECTED with 3 CommitmentMismatch results', () => {
  const r = AT.runById('domain');
  assert.equal(r.verdict, 'REJECTED');
  const matches = codes(r).match(/CommitmentMismatch/g);
  assert.equal(matches.length, 3);
});

test('ATK 21: domain covers chain id, contract and session surfaces', () => {
  const r = AT.runById('domain');
  const l = labels(r).join(' | ');
  assert.match(l, /chain id 1/);
  assert.match(l, /twin vault contract/);
  assert.match(l, /different session id/);
});

// ---- 3. leaf reuse --------------------------------------------------------------

test('ATK 30: leaf-reuse verdict is BLOCKED', () => {
  const r = AT.runById('leaf-reuse');
  assert.equal(r.verdict, 'BLOCKED');
});

test('ATK 31: leaf-reuse shows LeafReused and LeafOutOfBounds guards', () => {
  const r = AT.runById('leaf-reuse');
  assert.match(codes(r), /LeafReused/);
  assert.match(codes(r), /LeafOutOfBounds/);
});

test('ATK 32: unguarded reuse counterfactual forges a valid signature', () => {
  const r = AT.runById('leaf-reuse');
  const cf = r.steps.find((s) => s.kind === 'compromised');
  assert.ok(cf, 'expected a compromised step showing the unguarded failure');
  assert.match(cf.detail, /verifies: true/);
  assert.match(cf.label, /256\/256/);
});

test('ATK 33: leaf-reuse reports the bitmap state after blocking', () => {
  const r = AT.runById('leaf-reuse');
  assert.match(codes(r), /usedBitmap\[0\]=1/);
  assert.match(codes(r), /nextLeaf=1/);
});

// ---- 4. merkle tamper ---------------------------------------------------------------

test('ATK 40: merkle-tamper verdict is REJECTED with all mutations failing', () => {
  const r = AT.runById('merkle-tamper');
  assert.equal(r.verdict, 'REJECTED');
  const rejected = r.steps.filter((s) => s.kind === 'rejected').length;
  assert.equal(rejected, 6);
  assert.match(r.summary, /6\/6/);
});

test('ATK 41: merkle-tamper covers sibling, order, index, length, forgery', () => {
  const r = AT.runById('merkle-tamper');
  const l = labels(r).join(' | ');
  for (const frag of ['deepest sibling', 'sibling order', 'neighbouring leaf index', 'truncate', 'extend', 'neighbouring leaf']) {
    assert.match(l, new RegExp(frag), frag);
  }
});

test('ATK 42: merkle-tamper never accepts a mutated bundle', () => {
  const r = AT.runById('merkle-tamper');
  assert.doesNotMatch(codes(r), /ACCEPTED - unexpected/);
});

// ---- 5. shor drain ----------------------------------------------------------------------

test('ATK 50: shor-drain verdict is PROTECTED with ECDSA COMPROMISED', () => {
  const r = AT.runById('shor-drain');
  assert.equal(r.verdict, 'PROTECTED');
  assert.equal(r.ecdsaVerdict, 'COMPROMISED');
});

test('ATK 51: shor-drain recovers the toy private key', () => {
  const r = AT.runById('shor-drain');
  const cf = r.steps.find((s) => s.kind === 'compromised');
  assert.ok(cf);
  assert.match(cf.detail, /recovered key 42/);
});

test('ATK 52: shor-drain sweeps all 101 scores with zero collisions', () => {
  const r = AT.runById('shor-drain');
  assert.match(codes(r), /0 candidate commitments collide/);
});

test('ATK 53: shor-drain redirect attempt dies at NotSessionActor', () => {
  const r = AT.runById('shor-drain');
  assert.match(codes(r), /NotSessionActor/);
});

test('ATK 54: shor-drain labels the toy curve honestly', () => {
  const r = AT.runById('shor-drain');
  assert.match(codes(r), /toy curve/);
});

// ---- 6. limit bypass ------------------------------------------------------------------------

test('ATK 60: limit-bypass verdict is BLOCKED', () => {
  const r = AT.runById('limit-bypass');
  assert.equal(r.verdict, 'BLOCKED');
  assert.equal(r.steps.length, 9);
});

test('ATK 61: limit-bypass fires the cap errors', () => {
  const r = AT.runById('limit-bypass');
  assert.match(codes(r), /PerTxCapExceeded/);
  assert.match(codes(r), /CumulativeCapExceeded/);
});

test('ATK 62: limit-bypass fires timelock then guardian gates', () => {
  const r = AT.runById('limit-bypass');
  assert.match(codes(r), /TimelockActive/);
  assert.match(codes(r), /GuardianApprovalMissing/);
});

test('ATK 63: limit-bypass rejects forged guardian and admin paths', () => {
  const r = AT.runById('limit-bypass');
  const c = codes(r);
  assert.match(c, /NotGuardian/);
  assert.match(c, /NotPayer/);
  const np = c.match(/NotSessionPayer/g);
  assert.equal(np.length, 2);
});

test('ATK 64: every limit-bypass step after setup is blocked', () => {
  const r = AT.runById('limit-bypass');
  for (const s of r.steps.slice(1)) {
    assert.equal(s.kind, 'blocked', s.label);
  }
});
