'use strict';

/* Unit tests for src/risk.js deterministic exposure scoring. */

const test = require('node:test');
const assert = require('node:assert/strict');
const R = require('../src/risk.js');

test('RISK 01: scoreToTier boundaries match contract tiers', () => {
  assert.equal(R.scoreToTier(0), 0);
  assert.equal(R.scoreToTier(29), 0);
  assert.equal(R.scoreToTier(30), 1);
  assert.equal(R.scoreToTier(59), 1);
  assert.equal(R.scoreToTier(60), 2);
  assert.equal(R.scoreToTier(84), 2);
  assert.equal(R.scoreToTier(85), 3);
  assert.equal(R.scoreToTier(100), 3);
});

test('RISK 02: scoreToTier rejects out of range input', () => {
  assert.throws(() => R.scoreToTier(-1), RangeError);
  assert.throws(() => R.scoreToTier(101), RangeError);
  assert.throws(() => R.scoreToTier(45.5), RangeError);
});

test('RISK 03: base scores for known schemes', () => {
  const a = R.exposureScore({ scheme: 'secp256k1' });
  assert.equal(a.score, 55);
  assert.equal(a.tierName, 'medium');
  const b = R.exposureScore({ scheme: 'ml-dsa-65' });
  assert.equal(b.score, 6);
  assert.equal(b.tierName, 'low');
  const c = R.exposureScore({ scheme: 'rsa-2048' });
  assert.equal(c.score, 70);
  assert.equal(c.tierName, 'high');
});

test('RISK 04: modifiers stack additively', () => {
  const s = R.exposureScore({
    scheme: 'secp256k1', keyRevealed: true, deprecated: true,
    valueTusd: 15000, ageDays: 500
  });
  // 55 + 20 + 10 + 15 + 5 = 105 -> clamped 100
  assert.equal(s.score, 100);
  assert.equal(s.tier, 3);
  assert.equal(s.factors.length, 5);
});

test('RISK 05: value steps pick the highest matching tier only', () => {
  const small = R.exposureScore({ scheme: 'ml-dsa-44', valueTusd: 150 });
  assert.equal(small.score, 12); // 8 + 4
  const mid = R.exposureScore({ scheme: 'ml-dsa-44', valueTusd: 2000 });
  assert.equal(mid.score, 16); // 8 + 8, not 8 + 4 + 8
  const big = R.exposureScore({ scheme: 'ml-dsa-44', valueTusd: 99999 });
  assert.equal(big.score, 23); // 8 + 15
});

test('RISK 06: determinism across repeated calls', () => {
  const in1 = { scheme: 'ed25519', keyRevealed: true, valueTusd: 250, ageDays: 90, deprecated: false };
  const a = R.exposureScore(in1);
  const b = R.exposureScore(in1);
  assert.deepEqual(a, b);
});

test('RISK 07: unknown scheme and bad inputs rejected', () => {
  assert.throws(() => R.exposureScore({ scheme: 'made-up-1' }), TypeError);
  assert.throws(() => R.exposureScore({ scheme: 'secp256k1', valueTusd: -4 }), TypeError);
  assert.throws(() => R.exposureScore({ scheme: 'secp256k1', ageDays: NaN }), TypeError);
});

test('RISK 08: every scheme base score stays under critical alone', () => {
  for (const scheme of Object.keys(R.SCHEME_BASE)) {
    const s = R.exposureScore({ scheme });
    assert.ok(s.score <= 70, scheme + ' base ' + s.score);
    assert.ok(s.score >= 0);
  }
});

test('RISK 09: tier labels align with chain constants', () => {
  assert.equal(R.tierName(0), 'low');
  assert.equal(R.tierName(1), 'medium');
  assert.equal(R.tierName(2), 'high');
  assert.equal(R.tierName(3), 'critical');
});

test('RISK 10: a full risk route can reach each tier', () => {
  assert.equal(R.exposureScore({ scheme: 'ml-dsa-87' }).tier, 0);
  assert.equal(R.exposureScore({ scheme: 'secp256k1' }).tier, 1);
  assert.equal(R.exposureScore({ scheme: 'rsa-2048' }).tier, 2);
  assert.equal(R.exposureScore({ scheme: 'rsa-2048', keyRevealed: true, deprecated: true }).tier, 3);
});

test('RISK 11: prototype keys are rejected as unknown schemes', () => {
  for (const scheme of ['toString', '__proto__', 'constructor', 'hasOwnProperty']) {
    assert.throws(() => R.exposureScore({ scheme }), /unknown scheme/);
  }
});
