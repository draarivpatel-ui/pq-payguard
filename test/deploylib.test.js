'use strict';

/*
 * Tests for scripts/lib/eth.mjs: secp256k1 key derivation against the well
 * known anvil accounts, RLP reference vectors, and EIP-155 signing verified
 * mathematically through public key recovery.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

let eth;
test.before(async () => {
  eth = await import('../scripts/lib/eth.mjs');
});

const K = require('../src/keccak.js');

test('SECP 01: well known development account derivations', async () => {
  assert.equal(eth.privateKeyToAddress(1n), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
  assert.equal(eth.privateKeyToAddress(2n), '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf');
});

test('SECP 02: key validity range', async () => {
  assert.equal(eth.isValidPrivateKey(0n), false);
  assert.equal(eth.isValidPrivateKey(1n), true);
  assert.equal(eth.isValidPrivateKey(eth.ORDER_N), false);
  assert.equal(eth.isValidPrivateKey(eth.ORDER_N - 1n), true);
});

test('RLP 01: reference vectors from the ethereum docs', async () => {
  const B = K.utf8Bytes;
  const hex = (u8) => K.bytesToHex(u8);
  assert.equal(hex(eth.rlpEncode(B('dog'))), '83646f67');
  assert.equal(hex(eth.rlpEncode([B('cat'), B('dog')])), 'c88363617483646f67');
  assert.equal(hex(eth.rlpEncode(new Uint8Array(0))), '80');
  assert.equal(hex(eth.rlpEncode([])), 'c0');
  assert.equal(hex(eth.rlpEncode(1024n)), '820400');
  assert.equal(hex(eth.rlpEncode(0n)), '80'); // empty string encoding for zero
});

// Recover the secp256k1 public key point from (r, s, recid, z).
function recoverPoint(r, s, recid, zBytes) {
  const { pointMul, pointAdd, powMod, mod, G, ORDER_N, FIELD_P } = eth;
  const x = r + BigInt(recid >> 1) * ORDER_N;
  const alpha = mod(x * x % FIELD_P * x + 7n, FIELD_P);
  let y = powMod(alpha, (FIELD_P + 1n) / 4n, FIELD_P);
  if (Number(y & 1n) !== (recid & 1)) y = FIELD_P - y;
  const R = { x, y };
  const z = mod(BigInt('0x' + K.bytesToHex(zBytes)), ORDER_N);
  const rinv = powMod(r, ORDER_N - 2n, ORDER_N);
  const u1 = mod(-z * rinv, ORDER_N);
  const u2 = mod(s * rinv, ORDER_N);
  return pointAdd(pointMul(u1, G), pointMul(u2, R));
}

function addressOfPoint(q) {
  const buf = new Uint8Array(64);
  let x = q.x, y = q.y;
  for (let i = 31; i >= 0; i--) { buf[i] = Number(x & 0xffn); x >>= 8n; }
  for (let i = 63; i >= 32; i--) { buf[i] = Number(y & 0xffn); y >>= 8n; }
  return '0x' + K.bytesToHex(K.keccak256(buf).slice(12));
}

test('SECP 03: signature recovers the signer address (mathematical verify)', async () => {
  const priv = 0x4bd8n ** 2n + 0x12345n; // arbitrary deterministic test key
  const digest = K.keccak256(K.utf8Bytes('pq-payguard-sign-test'));
  const { r, s, recid } = await eth.signDigest(priv, digest);
  const q = recoverPoint(r, s, recid, digest);
  assert.equal(addressOfPoint(q), eth.privateKeyToAddress(priv));
});

test('SECP 04: low-s normalisation is applied', async () => {
  for (let i = 1; i <= 8; i++) {
    const digest = K.keccak256(K.utf8Bytes('low-s-' + i));
    const { s } = await eth.signDigest(BigInt(i * 977 + 1), digest);
    assert.ok(s <= eth.ORDER_N / 2n, 's above n/2 on iter ' + i);
  }
});

test('TX 01: EIP-155 legacy signing structure', async () => {
  const priv = 1n;
  const signed = await eth.signLegacyTransaction(priv, {
    nonce: 0n, gasPrice: 1_000_000_000n, gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 1n, data: '0x', chainId: 44005n
  });
  assert.match(signed.raw, /^0xf8/);
  // v must be chainId * 2 + 35 or 36
  const v = 44005n * 2n + 35n;
  assert.ok(signed.v === v || signed.v === v + 1n, 'v ' + signed.v);
});

test('TX 02: same input produces identical signature (RFC 6979)', async () => {
  const priv = 42n;
  const tx = {
    nonce: 3n, gasPrice: 2_000_000_000n, gasLimit: 100000n,
    to: '0x0000000000000000000000000000000000000bb2',
    value: 0n, data: '0xa9059cbb', chainId: 44005n
  };
  const a = await eth.signLegacyTransaction(priv, tx);
  const b = await eth.signLegacyTransaction(priv, tx);
  assert.equal(a.raw, b.raw);
  assert.equal(a.hash, b.hash);
});
