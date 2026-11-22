'use strict';

/*
 * Tests for src/receipt.js: SHA-256 signed receipts, detached WOTS
 * verification, CSV injection-safe export and the #pq= bookmark codec.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const RC = require('../src/receipt.js');
const PQ = require('../src/pqsig.js');
const K = require('../src/keccak.js');

const SEED = K.keccak256(K.utf8Bytes('receipt-test-wallet'));

function wallet() {
  return new PQ.HashWallet({ height: 3, scheme: 'wots', w: 16, seed: SEED });
}

const PAYLOAD = {
  scoreInputs: { scheme: 'secp256k1', value: 500, ageDays: 30, keyRevealed: false, deprecated: false },
  score: 55,
  verdicts: ['replay=REJECTED']
};

// ---- build ----------------------------------------------------------------

test('RC 01: unsigned receipt shape', async () => {
  const r = await RC.buildReceipt(PAYLOAD, { chainId: 44005, issuedAt: 1765000000 });
  assert.equal(r.body.v, 1);
  assert.equal(r.body.app, 'pq-payguard');
  assert.equal(r.body.kind, 'verification-receipt');
  assert.equal(r.body.chainId, 44005);
  assert.equal(r.body.issuedAt, 1765000000);
  assert.match(r.digest, /^0x[0-9a-f]{64}$/);
  assert.equal(r.signature, undefined);
});

test('RC 02: receipt digest is deterministic for identical bodies', async () => {
  const a = await RC.buildReceipt(PAYLOAD, { issuedAt: 100 });
  const b = await RC.buildReceipt({ score: 55, scoreInputs: PAYLOAD.scoreInputs, verdicts: ['replay=REJECTED'] }, { issuedAt: 100 });
  assert.equal(a.digest, b.digest);
});

test('RC 03: receipt digest changes on payload tamper', async () => {
  const a = await RC.buildReceipt(PAYLOAD, { issuedAt: 100 });
  const b = await RC.buildReceipt(Object.assign({}, PAYLOAD, { score: 56 }), { issuedAt: 100 });
  assert.notEqual(a.digest, b.digest);
});

test('RC 04: receipt digest changes on chain id tamper', async () => {
  const a = await RC.buildReceipt(PAYLOAD, { chainId: 44005, issuedAt: 100 });
  const b = await RC.buildReceipt(PAYLOAD, { chainId: 1, issuedAt: 100 });
  assert.notEqual(a.digest, b.digest);
});

test('RC 05: signed receipt carries wots bundle and merkle root', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  assert.equal(r.signature.scheme, 'wots');
  assert.equal(r.signature.w, 16);
  assert.equal(r.signature.leafIndex, 0);
  assert.equal(r.signature.treeHeight, 3);
  assert.match(r.signature.merkleRoot, /^0x[0-9a-f]{64}$/);
  assert.equal(r.signature.sig.length, 67);
  assert.equal(r.signature.proof.length, 3);
});

// ---- verify -------------------------------------------------------------------

test('RC 10: honest unsigned receipt verifies', async () => {
  const r = await RC.buildReceipt(PAYLOAD, { issuedAt: 100 });
  const v = await RC.verifyReceipt(r);
  assert.equal(v.ok, true);
  assert.ok(v.checks.every((c) => c.ok));
});

test('RC 11: honest signed receipt verifies detached', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const v = await RC.verifyReceipt(r);
  assert.equal(v.ok, true);
  assert.equal(v.checks.length, 4);
  assert.equal(v.checks[2].name, 'one time signature valid');
});

test('RC 12: tampered payload fails the digest check', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const t = JSON.parse(JSON.stringify(r));
  t.body.payload.score = 99;
  const v = await RC.verifyReceipt(t);
  assert.equal(v.ok, false);
  const dig = v.checks.find((c) => c.name === 'sha256 digest recomputes');
  assert.equal(dig.ok, false);
});

test('RC 13: tampered signature fails verification', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const t = JSON.parse(JSON.stringify(r));
  // flip a byte in one chain element
  const el = t.signature.sig[0].replace(/^0x../, '0xff');
  t.signature.sig[0] = el;
  const v = await RC.verifyReceipt(t);
  assert.equal(v.ok, false);
});

test('RC 14: tampered leaf index fails verification', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const t = JSON.parse(JSON.stringify(r));
  t.signature.leafIndex = 1;
  const v = await RC.verifyReceipt(t);
  assert.equal(v.ok, false);
});

test('RC 15: tampered merkle root fails verification', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const t = JSON.parse(JSON.stringify(r));
  t.signature.merkleRoot = '0x' + '00'.repeat(32);
  const v = await RC.verifyReceipt(t);
  assert.equal(v.ok, false);
  const leaf = v.checks.find((c) => c.name === 'merkle root anchors the leaf');
  assert.equal(leaf.ok, false);
});

test('RC 16: tampered proof sibling fails verification', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const t = JSON.parse(JSON.stringify(r));
  t.signature.proof[0].sibling = '0x' + 'ab'.repeat(32);
  const v = await RC.verifyReceipt(t);
  assert.equal(v.ok, false);
});

test('RC 17: malformed receipt fails closed, never throws', async () => {
  for (const bad of [null, undefined, {}, { body: null }, { body: { kind: 'x', v: 99 } }, 'str', 42]) {
    const v = await RC.verifyReceipt(bad);
    assert.equal(v.ok, false, JSON.stringify(bad));
  }
});

test('RC 18: malformed signature bundle fails closed', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const t = JSON.parse(JSON.stringify(r));
  t.signature.sig = ['0xzz'];
  const v = await RC.verifyReceipt(t);
  assert.equal(v.ok, false);
});

test('RC 19: wallet leaf budget decreases per signed receipt', async () => {
  const w = wallet();
  await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 1 });
  await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 2 });
  assert.equal(w.remaining(), 6);
  const r3 = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 3 });
  assert.equal(r3.signature.leafIndex, 2);
});

test('RC 20: two receipts from the same wallet verify independently', async () => {
  const w = wallet();
  const r1 = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 1 });
  const r2 = await RC.buildReceipt({ other: true }, { wallet: w, issuedAt: 2 });
  assert.notEqual(r1.signature.merkleRoot, undefined);
  assert.equal((await RC.verifyReceipt(r1)).ok, true);
  assert.equal((await RC.verifyReceipt(r2)).ok, true);
});

// ---- CSV ------------------------------------------------------------------------

test('RC 30: csvCell quotes every field', () => {
  assert.equal(RC.csvCell('plain'), '"plain"');
  assert.equal(RC.csvCell(42), '"42"');
  assert.equal(RC.csvCell(null), '""');
  assert.equal(RC.csvCell(undefined), '""');
});

test('RC 31: csvCell doubles inner quotes', () => {
  assert.equal(RC.csvCell('say "hi"'), '"say ""hi"""');
});

test('RC 32: csvCell neutralizes formula injection', () => {
  for (const evil of ['=1+1', '+cmd', '-2+3', '@sum(A1)', '\t=x', '\r=1']) {
    const cell = RC.csvCell(evil);
    assert.ok(cell.startsWith('"\''), 'unescaped: ' + JSON.stringify(evil));
  }
});

test('RC 33: csvCell passes safe values untouched', () => {
  assert.equal(RC.csvCell('=safe-text'), '"\'=safe-text"'); // leading = still escaped
  assert.equal(RC.csvCell('normal'), '"normal"');
  assert.equal(RC.csvCell(' - leading space equals'), '" - leading space equals"');
});

test('RC 34: toCsv joins rows with CRLF and trailing newline', () => {
  const out = RC.toCsv([['a', 'b'], ['1', '2']]);
  assert.equal(out, '"a","b"\r\n"1","2"\r\n');
});

test('RC 35: receiptToCsv contains digest and checks', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const v = await RC.verifyReceipt(r);
  const csv = RC.receiptToCsv(r, v);
  assert.match(csv, /"digest","0x[0-9a-f]{64}"/);
  assert.match(csv, /"signature scheme","wots"/);
  assert.match(csv, /"one time signature valid","pass"/);
});

test('RC 36: receiptToCsv escapes injection in payload fields', async () => {
  const w = wallet();
  const r = await RC.buildReceipt({ note: '=2+3' }, { wallet: w, issuedAt: 100 });
  const csv = RC.receiptToCsv(r, null);
  assert.doesNotMatch(csv, /,"=/);
});

test('RC 37: receiptToMarkdown renders a table', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const v = await RC.verifyReceipt(r);
  const md = RC.receiptToMarkdown(r, v);
  assert.match(md, /# PQ PayGuard verification receipt/);
  assert.match(md, /\| chain id \| 44005 \|/);
  assert.match(md, /\| one time signature valid \| pass \|/);
});

test('RC 38: markdown detail pipes are neutralized', async () => {
  const w = wallet();
  const r = await RC.buildReceipt(PAYLOAD, { wallet: w, issuedAt: 100 });
  const v = await RC.verifyReceipt(r);
  v.checks.push({ name: 'x', ok: false, detail: 'a|b' });
  const md = RC.receiptToMarkdown(r, v);
  assert.match(md, /a\/b/);
});

// ---- bookmark codec ------------------------------------------------------------

const SC = { scheme: 'secp256k1', value: 500, age: 30, revealed: false, deprecated: true };

test('RC 50: bookmark round trip', () => {
  const frag = RC.encodeBookmark(SC);
  assert.match(frag, /^pq=[A-Za-z0-9_-]+\.[0-9a-f]{8}$/);
  const d = RC.decodeBookmark('#' + frag);
  assert.deepEqual(d, SC);
});

test('RC 51: bookmark decode accepts raw fragment without #', () => {
  const frag = RC.encodeBookmark(SC);
  const d = RC.decodeBookmark(frag);
  assert.equal(d.scheme, 'secp256k1');
});

test('RC 52: bookmark checksum catches a flipped character', () => {
  const frag = RC.encodeBookmark(SC);
  const mid = frag.slice(3, frag.indexOf('.'));
  const i = 3 + Math.floor(mid.length / 2);
  const flipped = frag.slice(0, i) + (frag[i] === 'A' ? 'B' : 'A') + frag.slice(i + 1);
  assert.throws(() => RC.decodeBookmark(flipped), /checksum/);
});

test('RC 53: bookmark rejects bad shapes', () => {
  assert.throws(() => RC.decodeBookmark(''), /not a pq bookmark/);
  assert.throws(() => RC.decodeBookmark('#other=xyz'), /not a pq bookmark/);
  assert.throws(() => RC.decodeBookmark('pq=aaaa'), /checksum/);
  assert.throws(() => RC.decodeBookmark('pq=aaaa.00000000'), /checksum mismatch/);
});

test('RC 54: bookmark payload must decode to v1 JSON', () => {
  const payload = RC.b64urlEncode(K.utf8Bytes('{"v":2,"scheme":"x"}'));
  const frag = 'pq=' + payload + '.' + RC.fnv1a(payload);
  assert.throws(() => RC.decodeBookmark(frag), /version/);
});

test('RC 55: bookmark with corrupted base64 body fails decode', () => {
  const payload = RC.b64urlEncode(K.utf8Bytes('not json at all'));
  const frag = 'pq=' + payload + '.' + RC.fnv1a(payload);
  assert.throws(() => RC.decodeBookmark(frag), /JSON/);
});

test('RC 56: bookmark booleans coerce strictly', () => {
  const d = RC.decodeBookmark(RC.encodeBookmark({ revealed: 1, deprecated: 'yes' }));
  assert.equal(d.revealed, true);
  assert.equal(d.deprecated, true);
});

test('RC 57: bookmark numbers coerce', () => {
  const d = RC.decodeBookmark(RC.encodeBookmark({ value: '750', age: '12' }));
  assert.equal(d.value, 750);
  assert.equal(d.age, 12);
});

test('RC 58: bookmark whitelist drops extra fields', () => {
  const d = RC.decodeBookmark(RC.encodeBookmark({ scheme: 'falcon-512', evil: 'alert(1)', value: 1 }));
  assert.equal(d.evil, undefined);
  assert.equal(d.scheme, 'falcon-512');
});

// ---- b64url + fnv ----------------------------------------------------------------

test('RC 60: b64url round trip', () => {
  const bytes = K.utf8Bytes('hello payguard ~$%^&*()');
  const enc = RC.b64urlEncode(bytes);
  assert.doesNotMatch(enc, /[+/=]/);
  assert.deepEqual(Array.from(RC.b64urlDecode(enc)), Array.from(bytes));
});

test('RC 61: b64url handles empty and single byte', () => {
  assert.equal(RC.b64urlEncode(new Uint8Array(0)), '');
  const enc = RC.b64urlEncode(new Uint8Array([65]));
  assert.deepEqual(Array.from(RC.b64urlDecode(enc)), [65]);
});

test('RC 62: fnv1a is deterministic and 8 hex chars', () => {
  const a = RC.fnv1a('payload');
  const b = RC.fnv1a('payload');
  const c = RC.fnv1a('payload2');
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{8}$/);
});

test('RC 63: fnv1a known value', () => {
  // FNV-1a 32-bit of 'a' is a published constant
  assert.equal(RC.fnv1a('a'), 'e40c292c');
});
