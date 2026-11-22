'use strict';

/*
 * Attestation and commitment binding tests. The commitment must equal the
 * contract's computeCommitment output byte for byte; test/anvil.test.js
 * verifies this against live bytecode, these tests pin the deterministic
 * construction and tamper behaviour locally.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../src/commit.js');
const K = require('../src/keccak.js');
const A = require('../src/abi.js');

const PAYER = '0x0000000000000000000000000000000000000aa1';
const RECIP = '0x0000000000000000000000000000000000000bb2';
const CONTRACT = '0x' + '11'.repeat(20);

function commitArgs(over) {
  return Object.assign({
    chainId: 44005,
    contractAddress: CONTRACT,
    sessionId: 0,
    payer: PAYER,
    recipient: RECIP,
    amountRaw: 250500000n,
    riskScore: 42,
    attestationHash: '0x' + 'ab'.repeat(32),
    deadline: 1765000000
  }, over || {});
}

test('COMMIT 01: attestation is deterministic', async () => {
  const input = {
    payer: PAYER, recipient: RECIP, amountRaw: 250500000n,
    score: 42, tier: 'medium', scheme: 'secp256k1',
    factors: [{ label: 'base secp256k1', points: 55 }],
    sessionId: 0, nonce: '7', issuedAt: 1764000000
  };
  const a = await C.buildAttestation(input);
  const b = await C.buildAttestation(input);
  assert.equal(a.attestationHash, b.attestationHash);
  assert.match(a.attestationHash, /^0x[0-9a-f]{64}$/);
});

test('COMMIT 02: canonical string sorts keys', () => {
  assert.equal(
    C.canonicalString({ b: 1, a: 2, c: { z: 1, y: 2 } }),
    '{"a":2,"b":1,"c":{"y":2,"z":1}}'
  );
});

test('COMMIT 03: attestation changes on any field tamper', async () => {
  const base = {
    payer: PAYER, recipient: RECIP, amountRaw: 100n, score: 10,
    tier: 'low', scheme: 'ml-dsa-65', factors: [], sessionId: 0, nonce: '1', issuedAt: 100
  };
  const a = await C.buildAttestation(base);
  const tampered = await C.buildAttestation(Object.assign({}, base, { score: 11 }));
  assert.notEqual(a.attestationHash, tampered.attestationHash);
});

test('COMMIT 04: commitment matches a hand computed keccak of the preimage', () => {
  const args = commitArgs();
  const encoded = A.encodeArgs(C.COMMITMENT_TYPES, [
    44005n, CONTRACT, 0n, PAYER, RECIP, 250500000n, 42n, '0x' + 'ab'.repeat(32), 1765000000n
  ]);
  const expected = '0x' + K.keccak256Hex(K.hexToBytes(encoded));
  assert.equal(C.computeCommitment(args), expected);
});

test('COMMIT 05: commitment is case insensitive on addresses', () => {
  const lower = C.computeCommitment(commitArgs());
  const upper = C.computeCommitment(commitArgs({
    payer: '0x0000000000000000000000000000000000000AA1',
    recipient: '0x0000000000000000000000000000000000000BB2'
  }));
  assert.equal(lower, upper);
});

test('COMMIT 06: every bound field changes the commitment', () => {
  const base = C.computeCommitment(commitArgs());
  const mutations = [
    { chainId: 1 },
    { contractAddress: '0x' + '22'.repeat(20) },
    { sessionId: 1 },
    { payer: '0x' + '33'.repeat(20) },
    { recipient: '0x' + '44'.repeat(20) },
    { amountRaw: 250500001n },
    { riskScore: 43 },
    { attestationHash: '0x' + 'cd'.repeat(32) },
    { deadline: 1765000001 }
  ];
  for (const m of mutations) {
    const key = Object.keys(m)[0];
    assert.notEqual(C.computeCommitment(commitArgs(m)), base,
      'unchanged for field ' + key);
  }
});

test('COMMIT 07: lowering the score breaks the commitment', () => {
  // the attack the gate exists to stop: attested at 80, caller submits 20
  const attested = C.computeCommitment(commitArgs({ riskScore: 80 }));
  const forged = C.computeCommitment(commitArgs({ riskScore: 20 }));
  assert.notEqual(attested, forged);
  assert.equal(C.verifyCommitment(attested, commitArgs({ riskScore: 20 })), false);
  assert.equal(C.verifyCommitment(attested, commitArgs({ riskScore: 80 })), true);
});

test('COMMIT 08: invalid inputs surface type errors', () => {
  assert.throws(() => C.computeCommitment(commitArgs({ recipient: '0x123' })), TypeError);
  assert.throws(() => C.computeCommitment(commitArgs({ attestationHash: '0x99' })), TypeError);
  assert.throws(() => C.computeCommitment(commitArgs({ riskScore: 256n })), RangeError);
});
