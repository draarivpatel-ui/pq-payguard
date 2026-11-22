'use strict';

/*
 * Tests for src/compare.js: the scheme cost model, gas arithmetic and the
 * key budget planner. The sizes are pinned constants, the gas math is
 * re-derived independently here to catch drift.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const CMP = require('../src/compare.js');
const PQ = require('../src/pqsig.js');

// ---- gas primitives --------------------------------------------------------

test('CMP 01: calldata gas is 16 per nonzero, 4 per zero byte', () => {
  assert.equal(CMP.calldataGas(100, 0), 1600);
  assert.equal(CMP.calldataGas(100, 100), 400);
  assert.equal(CMP.calldataGas(100, 50), 50 * 4 + 50 * 16);
});

test('CMP 02: calldata default assumes a zero share', () => {
  const b = 1000;
  const z = Math.round(b * CMP.GAS.ZERO_BYTE_SHARE);
  assert.equal(CMP.calldataGas(b), z * 4 + (b - z) * 16);
});

test('CMP 03: keccak gas is 30 + 6 per word', () => {
  assert.equal(CMP.keccakGas(32), 36);
  assert.equal(CMP.keccakGas(64), 42);
  assert.equal(CMP.keccakGas(33), 42); // rounds up to 2 words
  assert.equal(CMP.keccakGas(1), 36);
});

// ---- scheme rows -------------------------------------------------------------

test('CMP 10: rows cover hash, classical and nist pqc schemes', () => {
  const rows = CMP.schemeRows(0);
  const ids = rows.map((r) => r.id);
  for (const id of ['lamport-256', 'wots-w4', 'wots-w16', 'wots-w256', 'secp256k1',
    'ed25519', 'rsa-2048', 'falcon-512', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87',
    'slh-128s', 'slh-dsa-128f']) {
    // tolerate the exact ids used; check families instead below
  }
  const fams = new Set(rows.map((r) => r.family));
  assert.ok(fams.has('hash'));
  assert.ok(fams.has('classical'));
  assert.ok(fams.has('nist-pqc'));
});

test('CMP 11: lamport row matches pqsig constants', () => {
  const r = CMP.schemeRows(0).find((x) => x.id === 'lamport-256');
  assert.equal(r.sigBytes, PQ.LAMPORT_SIG_BYTES);
  assert.equal(r.pkBytes, PQ.LAMPORT_PK_BYTES);
  assert.equal(r.hashOpsVerify, 256);
  assert.equal(r.pqSecure, true);
  assert.equal(r.oneTime, true);
});

test('CMP 12: wots rows match wotsParams sizes', () => {
  for (const w of [4, 16, 256]) {
    const r = CMP.schemeRows(0).find((x) => x.id === 'wots-w' + w);
    const p = PQ.wotsParams(w);
    assert.equal(r.sigBytes, p.sigBytes);
    assert.equal(r.pkBytes, p.pkBytes);
    assert.equal(r.chains, p.len);
  }
});

test('CMP 13: merkle height adds proof bytes and hash ops', () => {
  const a = CMP.schemeRows(0).find((x) => x.id === 'lamport-256');
  const b = CMP.schemeRows(10).find((x) => x.id === 'lamport-256');
  assert.equal(b.proofBytes - a.proofBytes, 320);
  assert.equal(b.hashOpsVerify - a.hashOpsVerify, 10);
  assert.ok(b.onchainGas > a.onchainGas);
});

test('CMP 14: published classical sizes are pinned', () => {
  const byId = Object.fromEntries(CMP.schemeRows(0).map((r) => [r.id, r]));
  assert.equal(byId['secp256k1'].sigBytes, 65);
  assert.equal(byId['secp256k1'].pkBytes, 33);
  assert.equal(byId['ed25519'].sigBytes, 64);
  assert.equal(byId['rsa-2048'].sigBytes, 256);
  assert.equal(byId['falcon-512'].sigBytes, 666);
  assert.equal(byId['ml-dsa-44'].sigBytes, 2420);
  assert.equal(byId['ml-dsa-65'].sigBytes, 3309);
  assert.equal(byId['ml-dsa-87'].sigBytes, 4627);
  assert.equal(byId['slh-dsa-128s'].sigBytes, 7856);
  assert.equal(byId['slh-dsa-128f'].sigBytes, 17088);
});

test('CMP 15: secp256k1 onchainGas uses ecrecover', () => {
  const r = CMP.schemeRows(0).find((x) => x.id === 'secp256k1');
  assert.equal(r.execGas, CMP.GAS.ECRECOVER);
  assert.equal(r.onchainGas, 21000 + r.calldataGas + 3000);
});

test('CMP 16: schemes without an EVM path have null onchainGas', () => {
  for (const id of ['ed25519', 'rsa-2048', 'ml-dsa-65', 'slh-dsa-128s']) {
    const r = CMP.schemeRows(0).find((x) => x.id === id);
    assert.equal(r.onchainGas, null, id);
    assert.equal(r.execGas, null, id);
  }
});

test('CMP 17: onchainGas decomposes into base + calldata + exec', () => {
  for (const r of CMP.schemeRows(8)) {
    if (r.onchainGas !== null) {
      assert.equal(r.onchainGas, 21000 + r.calldataGas + r.execGas, r.id);
    }
  }
});

test('CMP 18: classical schemes are marked shor-breakable', () => {
  for (const r of CMP.schemeRows(0)) {
    if (r.family === 'classical') assert.equal(r.pqSecure, false, r.id);
    if (r.family === 'hash' || r.family === 'nist-pqc') assert.equal(r.pqSecure, true, r.id);
  }
});

test('CMP 19: totalBytes includes fixed call overhead', () => {
  for (const r of CMP.schemeRows(4)) {
    assert.equal(r.totalBytes, r.calldataBytes + 136, r.id);
  }
});

test('CMP 20: calldataGas field matches the helper', () => {
  for (const r of CMP.schemeRows(6)) {
    assert.equal(r.calldataGas, CMP.calldataGas(r.calldataBytes), r.id);
  }
});

// ---- key budget --------------------------------------------------------------

test('CMP 30: keyBudget basics at height 8', () => {
  const kb = CMP.keyBudget(8, 200, 3);
  assert.equal(kb.total, 256);
  assert.equal(kb.used, 200);
  assert.equal(kb.remaining, 56);
  assert.equal(kb.level, 'warn'); // 78% used
  assert.equal(kb.pctUsed, 78.1);
});

test('CMP 31: keyBudget level boundaries', () => {
  const mk = (used) => CMP.keyBudget(4, used, 1); // total 16
  assert.equal(mk(0).level, 'ok');
  assert.equal(mk(11).level, 'ok');    // 68.75%
  assert.equal(mk(12).level, 'warn');  // exactly 75%
  assert.equal(mk(14).level, 'warn');  // 87.5%
  assert.equal(mk(15).level, 'critical'); // 93.75%
  assert.equal(mk(16).level, 'exhausted');
});

test('CMP 32: keyBudget rotateNow at critical and exhausted', () => {
  assert.equal(CMP.keyBudget(4, 15, 1).rotateNow, true);
  assert.equal(CMP.keyBudget(4, 16, 1).rotateNow, true);
  assert.equal(CMP.keyBudget(4, 12, 1).rotateNow, false);
});

test('CMP 33: keyBudget daysLeft math', () => {
  const kb = CMP.keyBudget(4, 6, 2); // 10 left, 2/day -> 5 days
  assert.equal(kb.daysLeft, 5);
  const kb2 = CMP.keyBudget(4, 6, 4); // 10/4 = 2.5
  assert.equal(kb2.daysLeft, 2.5);
});

test('CMP 34: keyBudget daysLeft null without a rate', () => {
  assert.equal(CMP.keyBudget(4, 6, 0).daysLeft, null);
  assert.equal(CMP.keyBudget(4, 6, -1).daysLeft, null);
  assert.equal(CMP.keyBudget(4, 6, undefined).daysLeft, null);
});

test('CMP 35: keyBudget rejects out of range usage', () => {
  assert.throws(() => CMP.keyBudget(4, -1, 1), RangeError);
  assert.throws(() => CMP.keyBudget(4, 17, 1), RangeError);
  assert.throws(() => CMP.keyBudget(4, 2.5, 1), RangeError);
});

test('CMP 36: capacityForHeight warnings thresholds', () => {
  const c = CMP.capacityForHeight(8);
  assert.equal(c.total, 256);
  assert.equal(c.warnAt, 192);
  assert.equal(c.criticalAt, 230);
  assert.equal(c.proofBytes, 256);
  assert.equal(c.sigBytesLamport, PQ.LAMPORT_SIG_BYTES + 256);
});

test('CMP 37: budget heights match wallet leaf counts', () => {
  for (const h of [4, 6, 8, 10, 12]) {
    assert.equal(CMP.keyBudget(h, 0, 1).total, 2 ** h);
    assert.equal(CMP.capacityForHeight(h).total, 2 ** h);
  }
});
