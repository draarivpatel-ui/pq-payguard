'use strict';

/* Unit tests for src/keccak.js and src/abi.js. */

const test = require('node:test');
const assert = require('node:assert/strict');
const K = require('../src/keccak.js');
const A = require('../src/abi.js');
const CH = require('../src/chain.js');

test('KECCAK 01: empty input vector', () => {
  assert.equal(
    K.keccak256Hex(''),
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
  );
});

test('KECCAK 02: abc vector', () => {
  assert.equal(
    K.keccak256Hex('abc'),
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
  );
});

test('KECCAK 03: multi block input over the 136 byte rate boundary', () => {
  const input = new Uint8Array(300).fill(0x61);
  // reference digest produced by cast keccak on the same 300 byte input
  assert.equal(
    K.keccak256Hex(input),
    '5b7e0e47a96f32a88b4f14ca177982790807c40e1a105742ba0fc1babe1ef826'
  );
});

test('KECCAK 04: function selectors', () => {
  assert.equal(A.selector('transfer(address,uint256)'), 'a9059cbb');
  assert.equal(A.selector('approve(address,uint256)'), '095ea7b3');
  assert.equal(A.selector('balanceOf(address)'), '70a08231');
  assert.equal(A.selector('decimals()'), '313ce567');
});

test('ABI 01: typesOf parses parameter lists', () => {
  assert.deepEqual(A.typesOf('release(uint256)'), ['uint256']);
  assert.deepEqual(A.typesOf('nextEscrowId()'), []);
  assert.deepEqual(
    A.typesOf(CH.ESCROW_ABI.createEscrow),
    ['uint256', 'address', 'uint256', 'uint8', 'bytes32', 'bytes32', 'uint64']
  );
});

test('ABI 02: address encoding is left padded', () => {
  const w = A.encodeWord('address', '0x00000000000000000000000000000000deadbeef');
  assert.equal(w, '0'.repeat(56) + 'deadbeef');
  assert.throws(() => A.encodeWord('address', '0x1234'), TypeError);
});

test('ABI 03: uint encoding bounds', () => {
  assert.equal(A.encodeWord('uint8', 255n), '0'.repeat(62) + 'ff');
  assert.throws(() => A.encodeWord('uint8', 256n), RangeError);
  assert.throws(() => A.encodeWord('uint64', -1n), RangeError);
  const max = (1n << 256n) - 1n;
  assert.equal(A.encodeWord('uint256', max), 'f'.repeat(64));
});

test('ABI 04: bytes32 and bool words', () => {
  const h = '0x' + 'ab'.repeat(32);
  assert.equal(A.encodeWord('bytes32', h), 'ab'.repeat(32));
  assert.throws(() => A.encodeWord('bytes32', '0x12'), TypeError);
  assert.equal(A.encodeWord('bool', true), '0'.repeat(63) + '1');
  assert.equal(A.encodeWord('bool', false), '0'.repeat(64));
});

test('ABI 05: encodeCall produces selector plus args', () => {
  const cd = A.encodeCall('balanceOf(address)', ['0x00000000000000000000000000000000cafebabe']);
  assert.equal(cd.slice(0, 10), '0x70a08231');
  assert.equal(cd.length, 10 + 64);
});

test('ABI 06: decode round trip for all static types', () => {
  const types = ['uint256', 'address', 'uint8', 'bytes32', 'bool', 'uint64'];
  const values = [
    123456789n,
    '0x0000000000000000000000000000000000000aa1',
    42n,
    '0x' + 'cd'.repeat(32),
    true,
    9999999999n
  ];
  const enc = A.encodeArgs(types, values);
  const dec = A.decodeArgs(types, enc);
  assert.deepEqual(dec, values);
});

test('ABI 07: decodeCallArgs validates selector and decodes', () => {
  const cd = A.encodeCall(CH.ESCROW_ABI.release, [7n]);
  assert.deepEqual(A.decodeCallArgs(CH.ESCROW_ABI.release, cd), [7n]);
  assert.throws(() => A.decodeCallArgs(CH.ESCROW_ABI.revokeEscrow, cd), TypeError);
});

test('ABI 08: string decoding for symbol() responses', () => {
  // abi.encode("tUSD8") = offset word, length word, padded data
  const data =
    '0x' +
    '20'.padStart(64, '0') +
    '5'.padStart(64, '0') +
    '7455534438'.padEnd(64, '0');
  assert.equal(A.decodeArgs(['string'], data)[0], 'tUSD8');
});

test('ABI 09: createSession calldata shape', () => {
  const cd = A.encodeCall(CH.ESCROW_ABI.createSession, [
    '0x0000000000000000000000000000000000000000',
    '0x00000000000000000000000000000000000006c1',
    500000000n,
    2000000000n,
    1765000000n,
    900n,
    14400n
  ]);
  // selector + 7 words
  assert.equal(cd.length, 10 + 7 * 64);
  const args = A.decodeCallArgs(CH.ESCROW_ABI.createSession, cd);
  assert.equal(args[2], 500000000n);
  assert.equal(args[6], 14400n);
});

test('CHAIN 01: parse and format token units', () => {
  assert.equal(CH.parseTokenUnits('1.5'), 1500000n);
  assert.equal(CH.parseTokenUnits('0.000001'), 1n);
  assert.equal(CH.parseTokenUnits('250.5'), 250500000n);
  assert.equal(CH.formatTokenUnits(1500000n), '1.5');
  assert.equal(CH.formatTokenUnits(250500000n), '250.5');
  assert.equal(CH.formatTokenUnits(1n), '0.000001');
  assert.throws(() => CH.parseTokenUnits('0.0000001'), TypeError);
  assert.throws(() => CH.parseTokenUnits('abc'), TypeError);
  assert.throws(() => CH.parseTokenUnits('-5'), TypeError);
});

test('CHAIN 02: official network constants', () => {
  assert.equal(CH.NETWORK.chainId, 44005);
  assert.equal(CH.NETWORK.chainIdHex, '0xabe5');
  assert.equal(CH.NETWORK.rpcUrl, 'https://rpc-test.qday.info');
  assert.equal(CH.TUSD8.address, '0x456569838f1d43009A91ebA4263147Afd7233483');
  assert.equal(CH.TUSD8.decimals, 6);
});

test('CHAIN 03: address validation', () => {
  assert.equal(CH.isValidAddress(CH.TUSD8.address), true);
  assert.equal(CH.isValidAddress('0x123'), false);
  assert.equal(CH.isValidAddress('notanaddr'), false);
  assert.equal(
    CH.normalizeAddress('0x456569838F1D43009A91EBA4263147AFD7233483'),
    '0x456569838f1d43009a91eba4263147afd7233483'
  );
});
