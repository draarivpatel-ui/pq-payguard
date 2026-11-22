'use strict';

/*
 * Unit tests for src/pqsig.js: Lamport OTS, WOTS, merkle trees, the
 * stateful HashWallet, detached verification and the toy ECDLP demo.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const PQ = require('../src/pqsig.js');
const K = require('../src/keccak.js');

const SEED = K.keccak256(K.utf8Bytes('pqsig-test-seed'));
const SEED2 = K.keccak256(K.utf8Bytes('pqsig-test-seed-2'));
const MSG = K.keccak256(K.utf8Bytes('pay 100 tUSD8 to 0xbb2'));
const MSG2 = K.keccak256(K.utf8Bytes('pay 999 tUSD8 to 0xdead'));
const MSG3 = K.keccak256(K.utf8Bytes('attacker chosen message'));

function flip(hash) {
  const b = Uint8Array.from(hash);
  b[0] ^= 0x01;
  return b;
}

// ---- Lamport ----------------------------------------------------------------

test('PQ 01: lamport keygen is deterministic per seed+leaf', () => {
  const a = lamportPair(SEED, 0);
  const b = lamportPair(SEED, 0);
  assert.deepEqual(a.pk[0][0], b.pk[0][0]);
  assert.deepEqual(a.pk[255][1], b.pk[255][1]);
});

function lamportPair(seed, leaf) {
  return PQ.lamportKeygen(seed, leaf);
}

test('PQ 02: lamport key material differs across leaf indices', () => {
  const a = lamportPair(SEED, 0);
  const b = lamportPair(SEED, 1);
  assert.notDeepEqual(a.pk[0][0], b.pk[0][0]);
});

test('PQ 03: lamport key material differs across seeds', () => {
  const a = lamportPair(SEED, 0);
  const b = lamportPair(SEED2, 0);
  assert.notDeepEqual(a.pk[5][1], b.pk[5][1]);
});

test('PQ 04: lamport keypair shapes', () => {
  const { sk, pk } = lamportPair(SEED, 0);
  assert.equal(sk.length, 256);
  assert.equal(pk.length, 256);
  assert.equal(pk[0][0].length, 32);
  assert.equal(sk[0][1].length, 32);
  assert.equal(PQ.LAMPORT_SIG_BYTES, 8192);
  assert.equal(PQ.LAMPORT_PK_BYTES, 16384);
  assert.equal(PQ.LAMPORT_SK_BYTES, 16384);
});

test('PQ 05: lamport sign/verify round trip', () => {
  const { sk, pk } = lamportPair(SEED, 0);
  const sig = PQ.lamportSign(sk, MSG);
  assert.equal(sig.length, 256);
  assert.equal(PQ.lamportVerify(pk, MSG, sig), true);
});

test('PQ 06: lamport verify rejects a different message', () => {
  const { sk, pk } = lamportPair(SEED, 0);
  const sig = PQ.lamportSign(sk, MSG);
  assert.equal(PQ.lamportVerify(pk, MSG2, sig), false);
});

test('PQ 07: lamport verify rejects a one bit flip in the digest', () => {
  const { sk, pk } = lamportPair(SEED, 0);
  const sig = PQ.lamportSign(sk, MSG);
  assert.equal(PQ.lamportVerify(pk, flip(MSG), sig), false);
});

test('PQ 08: lamport verify rejects a swapped signature element', () => {
  const { sk, pk } = lamportPair(SEED, 0);
  const sig = PQ.lamportSign(sk, MSG);
  const bad = sig.slice();
  bad[10] = sig[11];
  assert.equal(PQ.lamportVerify(pk, MSG, bad), false);
});

test('PQ 09: lamport verify rejects wrong length signature', () => {
  const { pk } = lamportPair(SEED, 0);
  assert.equal(PQ.lamportVerify(pk, MSG, new Array(255).fill(new Uint8Array(32))), false);
  assert.equal(PQ.lamportVerify(pk, MSG, 'not-an-array'), false);
});

test('PQ 10: lamport verify rejects wrong pk', () => {
  const { sk } = lamportPair(SEED, 0);
  const other = lamportPair(SEED, 1);
  const sig = PQ.lamportSign(sk, MSG);
  assert.equal(PQ.lamportVerify(other.pk, MSG, sig), false);
});

test('PQ 11: lamport sign requires a 32 byte digest', () => {
  const { sk } = lamportPair(SEED, 0);
  assert.throws(() => PQ.lamportSign(sk, new Uint8Array(16)), /BadDigest/);
});

test('PQ 12: lamport pk digest is deterministic and sensitive', () => {
  const { pk } = lamportPair(SEED, 0);
  const other = lamportPair(SEED, 1);
  const d1 = PQ.lamportPkDigest(pk);
  const d2 = PQ.lamportPkDigest(pk);
  assert.deepEqual(d1, d2);
  assert.notDeepEqual(d1, PQ.lamportPkDigest(other.pk));
});

test('PQ 13: lamportForge succeeds when two sigs cover the target', () => {
  const { sk } = lamportPair(SEED, 0);
  // complementary messages guarantee full coverage
  const h1 = new Uint8Array(32).fill(0x00);
  const h2 = new Uint8Array(32).fill(0xff);
  const s1 = PQ.lamportSign(sk, h1);
  const s2 = PQ.lamportSign(sk, h2);
  const forged = PQ.lamportForge(s1, h1, s2, h2, MSG);
  assert.ok(forged);
  const { pk } = lamportPair(SEED, 0);
  assert.equal(PQ.lamportVerify(pk, MSG, forged), true);
});

test('PQ 14: lamportForge returns null when coverage is incomplete', () => {
  const { sk } = lamportPair(SEED, 0);
  const h1 = new Uint8Array(32).fill(0x00);
  const h2 = new Uint8Array(32).fill(0x00);
  const s1 = PQ.lamportSign(sk, h1);
  const s2 = PQ.lamportSign(sk, h2);
  // both sigs reveal only the '0' halves; a target needing any '1' fails
  const target = new Uint8Array(32).fill(0xff);
  assert.equal(PQ.lamportForge(s1, h1, s2, h2, target), null);
});

test('PQ 15: lamportForgeMulti collects coverage across k signatures', () => {
  const { sk, pk } = lamportPair(SEED, 0);
  // complementary bit patterns guarantee full two sided coverage
  const hashes = [
    new Uint8Array(32).fill(0x00), new Uint8Array(32).fill(0xff),
    new Uint8Array(32).fill(0xaa)
  ];
  const sigs = hashes.map((h) => PQ.lamportSign(sk, h));
  const target = K.keccak256(K.utf8Bytes('victim tx'));
  const r = PQ.lamportForgeMulti(sigs, hashes, target);
  assert.equal(r.coverage, 256);
  assert.equal(r.missing, 0);
  assert.ok(r.forged);
  assert.equal(PQ.lamportVerify(pk, target, r.forged), true);
});

test('PQ 15b: lamportForgeMulti reports missing positions', () => {
  const { sk } = lamportPair(SEED, 0);
  const h0 = new Uint8Array(32).fill(0x00);
  const sigs = [PQ.lamportSign(sk, h0)];
  const target = new Uint8Array(32).fill(0xff);
  const r = PQ.lamportForgeMulti(sigs, [h0], target);
  assert.equal(r.coverage, 0);
  assert.equal(r.missing, 256);
  assert.equal(r.forged, null);
});

test('PQ 16: lamportForgeMulti reports coverage count', () => {
  const { sk } = lamportPair(SEED, 0);
  const h1 = new Uint8Array(32).fill(0x00);
  const h2 = new Uint8Array(32).fill(0xff);
  const r = PQ.lamportForgeMulti([PQ.lamportSign(sk, h1), PQ.lamportSign(sk, h2)], [h1, h2], MSG);
  assert.equal(r.coverage, 256);
  assert.ok(r.forged);
});

// ---- WOTS -------------------------------------------------------------------

test('PQ 20: wotsParams for RFC 8391 values', () => {
  const p4 = PQ.wotsParams(4);
  assert.equal(p4.len1, 128);
  assert.equal(p4.len, 133);
  assert.equal(p4.sigBytes, 4256);
  const p16 = PQ.wotsParams(16);
  assert.equal(p16.len1, 64);
  assert.equal(p16.len2, 3);
  assert.equal(p16.len, 67);
  assert.equal(p16.sigBytes, 2144);
  const p256 = PQ.wotsParams(256);
  assert.equal(p256.len1, 32);
  assert.equal(p256.len2, 2);
  assert.equal(p256.len, 34);
  assert.equal(p256.sigBytes, 1088);
});

test('PQ 21: wotsParams rejects non RFC values', () => {
  for (const w of [2, 8, 32, 64, 128, 0, -4, 1024]) {
    assert.throws(() => PQ.wotsParams(w), /BadWinternitzParam/);
  }
});

test('PQ 22: wotsDigits yields len digits each below w', () => {
  for (const w of [4, 16, 256]) {
    const p = PQ.wotsParams(w);
    const digits = PQ.wotsDigits(MSG, w);
    assert.equal(digits.length, p.len);
    for (const d of digits) {
      assert.ok(Number.isInteger(d));
      assert.ok(d >= 0 && d < w);
    }
  }
});

test('PQ 23: wotsDigits checksum matches specification', () => {
  const w = 16;
  const p = PQ.wotsParams(w);
  const digits = PQ.wotsDigits(MSG, w);
  let sum = 0;
  for (let i = 0; i < p.len1; i++) sum += (w - 1) - digits[i];
  // checksum digits encode `sum` base-w big-endian in the last len2 slots
  let recon = 0;
  for (let i = 0; i < p.len2; i++) recon = recon * w + digits[p.len1 + i];
  assert.equal(recon, sum);
});

test('PQ 24: wotsDigits deterministic and message bound', () => {
  const a = PQ.wotsDigits(MSG, 16);
  const b = PQ.wotsDigits(MSG, 16);
  const c = PQ.wotsDigits(MSG2, 16);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
});

test('PQ 25: wots sign/verify round trip at every w', () => {
  for (const w of [4, 16, 256]) {
    const { sk, pk } = PQ.wotsKeygen(SEED, w, 0);
    const sig = PQ.wotsSign(sk, w, MSG);
    assert.equal(PQ.wotsVerify(pk, w, MSG, sig), true, 'w=' + w);
  }
});

test('PQ 26: wots verify rejects wrong message', () => {
  const { sk, pk } = PQ.wotsKeygen(SEED, 16, 0);
  const sig = PQ.wotsSign(sk, 16, MSG);
  assert.equal(PQ.wotsVerify(pk, 16, MSG2, sig), false);
});

test('PQ 27: wots verify rejects signature under wrong w', () => {
  const { sk, pk } = PQ.wotsKeygen(SEED, 16, 0);
  const sig = PQ.wotsSign(sk, 16, MSG);
  // w=4 expects a longer chain vector
  assert.equal(PQ.wotsVerify(pk, 4, MSG, sig), false);
});

test('PQ 28: wots verify rejects mutated chain element', () => {
  const { sk, pk } = PQ.wotsKeygen(SEED, 16, 0);
  const sig = PQ.wotsSign(sk, 16, MSG);
  const bad = sig.slice();
  bad[0] = K.keccak256(sig[0]); // one extra chain step
  assert.equal(PQ.wotsVerify(pk, 16, MSG, bad), false);
});

test('PQ 29: wots pk from signature reconstructs the real pk', () => {
  const { sk, pk } = PQ.wotsKeygen(SEED, 16, 3);
  const sig = PQ.wotsSign(sk, 16, MSG);
  const recon = PQ.wotsPkFromSig(16, MSG, sig);
  assert.deepEqual(recon, pk);
});

test('PQ 30: wotsPkFromSig returns null on malformed sig', () => {
  assert.equal(PQ.wotsPkFromSig(16, MSG, []), null);
  assert.equal(PQ.wotsPkFromSig(16, MSG, null), null);
  assert.equal(PQ.wotsPkFromSig(16, MSG, new Array(66).fill(new Uint8Array(32))), null);
});

test('PQ 31: wots leaf digest is deterministic and index bound', () => {
  const a = PQ.wotsKeygen(SEED, 16, 0);
  const b = PQ.wotsKeygen(SEED, 16, 0);
  const c = PQ.wotsKeygen(SEED, 16, 1);
  assert.deepEqual(PQ.wotsLeafDigest(a.pk), PQ.wotsLeafDigest(b.pk));
  assert.notDeepEqual(PQ.wotsLeafDigest(a.pk), PQ.wotsLeafDigest(c.pk));
});

// ---- Merkle -----------------------------------------------------------------

function leafSet(n) {
  const leaves = [];
  for (let i = 0; i < n; i++) leaves.push(K.keccak256(K.utf8Bytes('leaf-' + i)));
  return leaves;
}

test('PQ 35: merkle root is deterministic', () => {
  const t1 = PQ.merkleBuild(leafSet(8));
  const t2 = PQ.merkleBuild(leafSet(8));
  assert.deepEqual(t1.root, t2.root);
  assert.equal(t1.height, 3);
});

test('PQ 36: merkle verify accepts every leaf proof', () => {
  const leaves = leafSet(8);
  const tree = PQ.merkleBuild(leaves);
  for (let i = 0; i < 8; i++) {
    const proof = PQ.merkleProof(tree, i);
    assert.equal(proof.length, 3);
    assert.equal(PQ.merkleVerify(tree.root, leaves[i], i, proof), true, 'leaf ' + i);
  }
});

test('PQ 37: merkle verify rejects wrong leaf index', () => {
  const leaves = leafSet(8);
  const tree = PQ.merkleBuild(leaves);
  const proof = PQ.merkleProof(tree, 2);
  assert.equal(PQ.merkleVerify(tree.root, leaves[2], 3, proof), false);
});

test('PQ 38: merkle verify rejects sibling bit flip', () => {
  const leaves = leafSet(8);
  const tree = PQ.merkleBuild(leaves);
  const proof = PQ.merkleProof(tree, 1);
  const bad = proof.map((p, j) => j === 0
    ? { sibling: flip(p.sibling), right: p.right }
    : p);
  assert.equal(PQ.merkleVerify(tree.root, leaves[1], 1, bad), false);
});

test('PQ 39: merkle verify rejects flipped direction flag', () => {
  const leaves = leafSet(8);
  const tree = PQ.merkleBuild(leaves);
  const proof = PQ.merkleProof(tree, 1);
  const bad = proof.map((p, j) => j === 0 ? { sibling: p.sibling, right: !p.right } : p);
  assert.equal(PQ.merkleVerify(tree.root, leaves[1], 1, bad), false);
});

test('PQ 40: merkle verify rejects truncated and extended proofs', () => {
  const leaves = leafSet(8);
  const tree = PQ.merkleBuild(leaves);
  const proof = PQ.merkleProof(tree, 4);
  assert.equal(PQ.merkleVerify(tree.root, leaves[4], 4, proof.slice(0, 2)), false);
  const extended = proof.concat([{ sibling: leaves[0], right: true }]);
  assert.equal(PQ.merkleVerify(tree.root, leaves[4], 4, extended), false);
});

test('PQ 41: merkle verify rejects proof from a different tree', () => {
  const leaves = leafSet(8);
  const tree = PQ.merkleBuild(leaves);
  const other = PQ.merkleBuild(leafSet(8).map((l) => flip(l)));
  const proof = PQ.merkleProof(tree, 0);
  assert.equal(PQ.merkleVerify(other.root, leaves[0], 0, proof), false);
});

test('PQ 42: merkle odd leaf duplication still verifies', () => {
  const leaves = leafSet(3);
  const tree = PQ.merkleBuild(leaves);
  for (let i = 0; i < 3; i++) {
    assert.equal(PQ.merkleVerify(tree.root, leaves[i], i, PQ.merkleProof(tree, i)), true);
  }
});

test('PQ 43: merkle handles non power of two sizes', () => {
  for (const n of [1, 2, 5, 7, 9, 13]) {
    const leaves = leafSet(n);
    const tree = PQ.merkleBuild(leaves);
    for (let i = 0; i < n; i++) {
      assert.equal(PQ.merkleVerify(tree.root, leaves[i], i, PQ.merkleProof(tree, i)), true, 'n=' + n + ' i=' + i);
    }
  }
});

test('PQ 44: merkleBuild rejects an empty tree', () => {
  assert.throws(() => PQ.merkleBuild([]), /EmptyTree/);
});

test('PQ 45: merkleVerify fails closed on malformed inputs', () => {
  const leaves = leafSet(4);
  const tree = PQ.merkleBuild(leaves);
  const proof = PQ.merkleProof(tree, 0);
  assert.equal(PQ.merkleVerify(tree.root, leaves[0], 0, 'garbage'), false);
  assert.equal(PQ.merkleVerify(tree.root, new Uint8Array(8), 0, proof), false);
  assert.equal(PQ.merkleVerify(tree.root, leaves[0], 0, [{ sibling: new Uint8Array(4), right: true }]), false);
});

// ---- HashWallet --------------------------------------------------------------

function newWallet(over) {
  return new PQ.HashWallet(Object.assign({ height: 3, scheme: 'lamport', seed: SEED }, over));
}

test('PQ 50: wallet root and size derive from height', () => {
  const w = newWallet({ height: 4 });
  assert.equal(w.size, 16);
  assert.equal(w.root.length, 32);
  assert.equal(w.remaining(), 16);
});

test('PQ 51: wallet sign consumes exactly one leaf', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  assert.equal(b.leafIndex, 0);
  assert.equal(w.remaining(), 7);
  assert.equal(w.leafUsed(0), true);
  assert.equal(w.leafUsed(1), false);
});

test('PQ 52: wallet sign bundle verifies against its own root', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const v = w.verify(MSG, b);
  assert.equal(v.ok, true, v.reason);
});

test('PQ 53: wallet verify rejects a replayed bundle on another digest', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const v = w.verify(MSG2, b);
  assert.equal(v.ok, false);
  assert.match(v.reason, /invalid/);
});

test('PQ 54: signWith a consumed leaf throws LeafReused', () => {
  const w = newWallet();
  w.signWith(0, MSG);
  assert.throws(() => w.signWith(0, MSG2), /LeafReused/);
});

test('PQ 55: signWith below the monotonic counter throws LeafReused', () => {
  const w = newWallet();
  w.signWith(4, MSG); // advances nextLeaf to 5
  assert.throws(() => w.signWith(2, MSG2), /LeafReused/);
});

test('PQ 56: signWith out of range throws LeafOutOfBounds', () => {
  const w = newWallet({ height: 2 });
  assert.throws(() => w.signWith(4, MSG), /LeafOutOfBounds/);
  assert.throws(() => w.signWith(-1, MSG), /LeafOutOfBounds/);
  assert.throws(() => w.signWith(2.5, MSG), /LeafOutOfBounds/);
});

test('PQ 57: exhausted wallet throws LeafExhausted', () => {
  const w = newWallet({ height: 1 }); // 2 leaves
  w.sign(MSG);
  w.sign(MSG2);
  assert.equal(w.remaining(), 0);
  assert.throws(() => w.sign(MSG3), /LeafExhausted/);
});

test('PQ 58: wallet rejects bad constructor params', () => {
  assert.throws(() => new PQ.HashWallet({ height: 0 }), /BadTreeHeight/);
  assert.throws(() => new PQ.HashWallet({ height: 13 }), /BadTreeHeight/);
  assert.throws(() => new PQ.HashWallet({ scheme: 'bogus' }), /BadScheme/);
  assert.throws(() => new PQ.HashWallet({ seed: 'short' }), /BadSeed/);
});

test('PQ 59: wots wallet round trip', () => {
  const w = new PQ.HashWallet({ height: 3, scheme: 'wots', w: 16, seed: SEED });
  const b = w.sign(MSG);
  assert.equal(b.scheme, 'wots');
  assert.equal(b.w, 16);
  assert.equal(b.sig.length, 67);
  assert.equal(w.verify(MSG, b).ok, true);
});

test('PQ 60: usedBitmap export captures spent leaves', () => {
  const w = newWallet();
  w.signWith(0, MSG);
  w.signWith(2, MSG2);
  const st = w.exportState();
  assert.equal(st.usedBitmap[0], 1);
  assert.equal(st.usedBitmap[1], 0);
  assert.equal(st.usedBitmap[2], 1);
  assert.equal(st.nextLeaf, 3);
});

// ---- detached verification -----------------------------------------------------

test('PQ 65: detached verify accepts an honest lamport bundle', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const bundle = {
    leafIndex: b.leafIndex, scheme: 'lamport',
    sig: b.sig, proof: b.proof, leafPk: w.leafPublicKey(b.leafIndex)
  };
  assert.equal(PQ.verifyDetached(w.root, MSG, bundle).ok, true);
});

test('PQ 66: detached verify rejects tampered lamport sig', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const sig = b.sig.slice();
  sig[3] = K.keccak256(sig[3]);
  const bundle = {
    leafIndex: 0, scheme: 'lamport', sig,
    proof: b.proof, leafPk: w.leafPublicKey(0)
  };
  assert.equal(PQ.verifyDetached(w.root, MSG, bundle).ok, false);
});

test('PQ 67: detached verify needs leafPk for lamport', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const r = PQ.verifyDetached(w.root, MSG, { leafIndex: 0, scheme: 'lamport', sig: b.sig, proof: b.proof });
  assert.equal(r.ok, false);
  assert.match(r.reason, /pk/);
});

test('PQ 68: detached wots verify recomputes pk from sig+msg', () => {
  const w = new PQ.HashWallet({ height: 3, scheme: 'wots', w: 16, seed: SEED });
  const b = w.sign(MSG);
  // no leafPk supplied: the verifier derives it
  const r = PQ.verifyDetached(w.root, MSG, {
    leafIndex: b.leafIndex, scheme: 'wots', w: 16, sig: b.sig, proof: b.proof
  });
  assert.equal(r.ok, true, r.reason);
});

test('PQ 69: detached verify rejects wrong root', () => {
  const w = newWallet();
  const w2 = newWallet({ seed: SEED2 });
  const b = w.sign(MSG);
  const bundle = {
    leafIndex: 0, scheme: 'lamport', sig: b.sig,
    proof: b.proof, leafPk: w.leafPublicKey(0)
  };
  assert.equal(PQ.verifyDetached(w2.root, MSG, bundle).ok, false);
});

test('PQ 70: detached verify rejects out of range leaf index', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const r = PQ.verifyDetached(w.root, MSG, {
    leafIndex: -5, scheme: 'lamport', sig: b.sig, proof: b.proof, leafPk: w.leafPublicKey(0)
  });
  assert.equal(r.ok, false);
});

test('PQ 71: detached verify fails closed on bad root input', () => {
  const w = newWallet();
  const b = w.sign(MSG);
  const r = PQ.verifyDetached(new Uint8Array(9), MSG, {
    leafIndex: 0, scheme: 'lamport', sig: b.sig, proof: b.proof, leafPk: w.leafPublicKey(0)
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /root/);
});

// ---- toy ECDLP ------------------------------------------------------------------

test('PQ 75: toy curve scalar mul and point add obey group law', () => {
  const G = PQ.toyBasePoint();
  const a = PQ.toyScalarMul(3, G);
  const b = PQ.toyPointAdd(PQ.toyScalarMul(2, G), G);
  assert.deepEqual(a, b);
});

test('PQ 76: toy dlp solver recovers a known scalar', () => {
  const G = PQ.toyBasePoint();
  const Q = PQ.toyScalarMul(42, G);
  const d = PQ.toyDlpSolve(G, Q);
  assert.equal(d, 42);
});

test('PQ 77: toy dlp returns null for an off curve point', () => {
  const G = PQ.toyBasePoint();
  assert.equal(PQ.toyDlpSolve(G, [0, 0]), null);
});

test('PQ 78: toy curve identity element behaves', () => {
  const G = PQ.toyBasePoint();
  assert.deepEqual(PQ.toyPointAdd(G, null), G);
  assert.deepEqual(PQ.toyPointAdd(null, G), G);
  // P + (-P) = O
  const neg = [G[0], (PQ.TOY_P - G[1]) % PQ.TOY_P];
  assert.equal(PQ.toyPointAdd(G, neg), null);
});

test('PQ 79: toy scalar mul by zero gives identity', () => {
  const G = PQ.toyBasePoint();
  assert.equal(PQ.toyScalarMul(0, G), null);
});

// ---- digestBit -------------------------------------------------------------------

test('PQ 80: digestBit reads MSB first', () => {
  const h = new Uint8Array(32);
  h[0] = 0b10100000;
  assert.equal(PQ.digestBit(h, 0), 1);
  assert.equal(PQ.digestBit(h, 1), 0);
  assert.equal(PQ.digestBit(h, 2), 1);
  h[31] = 0b00000001;
  assert.equal(PQ.digestBit(h, 255), 1);
  assert.equal(PQ.digestBit(h, 254), 0);
});
