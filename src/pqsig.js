/*
 * Hash based signature lab for PQ PayGuard.
 *
 * Pure JavaScript, zero dependencies, built entirely on the in-repo
 * keccak256. Implements the one time and few time hash signature families
 * used by stateful post quantum wallets:
 *
 *   Lamport-256 OTS   : 256 key pairs, sign reveals one preimage per bit
 *   WOTS              : Winternitz chains at w = 4, 16, 64, 256
 *   Merkle tree       : keccak node hashing, sibling proofs, verification
 *   HashWallet        : XMSS style stateful wallet: a merkle tree of OTS
 *                       leaves behind a used leaf bitmap plus a monotonic
 *                       leaf counter. Signing with a consumed leaf throws
 *                       LeafReused, which is the exact guard that keeps a
 *                       stateful hash signature scheme one time.
 *
 * The module also carries a toy size elliptic curve DLP solver used by the
 * attack playground to demonstrate, at toy scale, what an exposed ECDSA
 * public key means once a large quantum computer runs Shor's algorithm.
 * It is labeled as an illustration, not a cryptanalytic claim.
 */
(function (root, factory) {
  let K;
  if (typeof module === 'object' && module.exports) {
    K = require('./keccak.js');
  } else {
    K = root.PQPG.keccak;
  }
  const api = factory(K);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.pqsig = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (K) {
  'use strict';

  class PqError extends Error {
    constructor(code, detail) {
      super(code + (detail !== undefined ? '(' + detail + ')' : ''));
      this.name = 'PqError';
      this.code = code;
      this.detail = detail;
    }
  }

  function fail(code, detail) {
    throw new PqError(code, detail);
  }

  function need32(h, what) {
    const b = h instanceof Uint8Array ? h : K.hexToBytes(h);
    if (b.length !== 32) fail('BadDigest', what || 'expected 32 bytes');
    return b;
  }

  function bytes32OrNull(x) {
    try {
      const b = x instanceof Uint8Array ? x : K.hexToBytes(x);
      return b.length === 32 ? b : null;
    } catch (e) {
      return null;
    }
  }

  function eq32(a, b) {
    if (!a || !b || a.length !== 32 || b.length !== 32) return false;
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ---- bit helpers -------------------------------------------------------

  // MSB first bit order, matching how signature schemes read a digest.
  function digestBit(digest, i) {
    return (digest[i >> 3] >> (7 - (i & 7))) & 1;
  }

  function seedBytes(seed) {
    if (typeof seed === 'string') {
      const s = seed.startsWith('0x') ? K.hexToBytes(seed) : K.utf8Bytes(seed);
      if (s.length !== 32) fail('BadSeed', 'seed must be 32 bytes');
      return s;
    }
    if (seed instanceof Uint8Array && seed.length === 32) return seed;
    fail('BadSeed', 'seed must be 32 bytes');
  }

  // ---- Lamport-256 OTS ---------------------------------------------------
  //
  // sk[i][b] = keccak256(seed || "lamport" || leaf || i || b)
  // pk[i][b] = keccak256(sk[i][b])
  // A signature reveals the 256 preimages selected by the message bits.
  // Signing two different digests with the same sk leaks both halves and
  // lets an attacker forge, which is why the wallet guards leaf reuse.

  const LAMPORT_SK_BYTES = 256 * 2 * 32;   // 16384
  const LAMPORT_SIG_BYTES = 256 * 32;      // 8192
  const LAMPORT_PK_BYTES = 256 * 2 * 32;   // 16384

  function _lamportSk(seed, leafIndex) {
    const sk = new Array(256);
    const tag = K.utf8Bytes('lamport');
    const leaf = new Uint8Array(4);
    leaf[0] = (leafIndex >>> 24) & 0xff;
    leaf[1] = (leafIndex >>> 16) & 0xff;
    leaf[2] = (leafIndex >>> 8) & 0xff;
    leaf[3] = leafIndex & 0xff;
    const idx = new Uint8Array(2);
    for (let i = 0; i < 256; i++) {
      idx[0] = (i >>> 8) & 0xff;
      idx[1] = i & 0xff;
      const zero = new Uint8Array([0]);
      const one = new Uint8Array([1]);
      sk[i] = [
        K.keccak256(K.concatBytes(seed, tag, leaf, idx, zero)),
        K.keccak256(K.concatBytes(seed, tag, leaf, idx, one))
      ];
    }
    return sk;
  }

  function lamportPublicKey(sk) {
    const pk = new Array(256);
    for (let i = 0; i < 256; i++) {
      pk[i] = [K.keccak256(sk[i][0]), K.keccak256(sk[i][1])];
    }
    return pk;
  }

  function lamportKeygen(seed, leafIndex) {
    const sk = _lamportSk(seedBytes(seed), leafIndex || 0);
    return { sk, pk: lamportPublicKey(sk) };
  }

  function lamportSign(sk, msgHash) {
    const m = need32(msgHash, 'message digest');
    const sig = new Array(256);
    for (let i = 0; i < 256; i++) sig[i] = sk[i][digestBit(m, i)];
    return sig;
  }

  function lamportVerify(pk, msgHash, sig) {
    const m = need32(msgHash, 'message digest');
    if (!Array.isArray(sig) || sig.length !== 256) return false;
    if (!Array.isArray(pk) || pk.length !== 256) return false;
    for (let i = 0; i < 256; i++) {
      const piece = bytes32OrNull(sig[i]);
      const pair = pk[i];
      if (!piece || !Array.isArray(pair) || pair.length !== 2) return false;
      const expect = bytes32OrNull(pair[digestBit(m, i)]);
      if (!expect || !eq32(K.keccak256(piece), expect)) return false;
    }
    return true;
  }

  // Compact leaf representation: one 32 byte digest of the whole pk blob.
  function lamportPkDigest(pk) {
    const flat = new Uint8Array(LAMPORT_PK_BYTES);
    let at = 0;
    for (let i = 0; i < 256; i++) {
      flat.set(pk[i][0], at); at += 32;
      flat.set(pk[i][1], at); at += 32;
    }
    return K.keccak256(flat);
  }

  /*
   * Given two signatures produced with the SAME Lamport key on DIFFERENT
   * digests, forge a signature on targetHash. Returns null when the union
   * of revealed preimages does not cover every bit position of the target.
   * This is the leaf reuse catastrophe in one function.
   */
  function lamportForge(sigA, hashA, sigB, hashB, targetHash) {
    const a = need32(hashA, 'hashA');
    const b = need32(hashB, 'hashB');
    const t = need32(targetHash, 'targetHash');
    const forged = new Array(256);
    for (let i = 0; i < 256; i++) {
      const want = digestBit(t, i);
      if (digestBit(a, i) === want) forged[i] = sigA[i];
      else if (digestBit(b, i) === want) forged[i] = sigB[i];
      else return null;
    }
    return forged;
  }

  /*
   * Multi signature version of the reuse catastrophe. `sigs` and `hashes`
   * are parallel arrays of signatures produced with the SAME Lamport key
   * on different digests. Returns { forged, coverage, known } where
   * coverage is the count of positions with both preimages revealed and
   * forged is the signature on targetHash (null if coverage incomplete).
   */
  function lamportForgeMulti(sigs, hashes, targetHash) {
    const t = need32(targetHash, 'targetHash');
    const known = new Array(256);
    for (let i = 0; i < 256; i++) known[i] = [null, null];
    const hs = hashes.map((h) => need32(h, 'signature digest'));
    for (let s = 0; s < sigs.length; s++) {
      for (let i = 0; i < 256; i++) {
        known[i][digestBit(hs[s], i)] = sigs[s][i];
      }
    }
    let coverage = 0;
    let missing = 0;
    const forged = new Array(256);
    for (let i = 0; i < 256; i++) {
      if (known[i][0] && known[i][1]) coverage++;
      forged[i] = known[i][digestBit(t, i)];
      if (!forged[i]) missing++;
    }
    return { forged: missing ? null : forged, coverage, missing, known };
  }

  // ---- WOTS (Winternitz one time signature) ------------------------------
  //
  // len1 base-w digits of the digest plus len2 checksum digits, each digit
  // driving a hash chain of length w - 1. Bigger w shrinks the signature
  // and inflates verification work, which is the classic WOTS trade-off.

  // w is restricted to the RFC 8391 values so every base-w digit lands on a
  // clean bit boundary inside the digest (w = 4, 16 or 256).
  function wotsParams(w) {
    if (![4, 16, 256].includes(w)) fail('BadWinternitzParam', 'w must be 4, 16 or 256');
    const bits = Math.log2(w);
    const len1 = Math.ceil(256 / bits);
    const len2 = Math.floor(Math.log(len1 * (w - 1)) / Math.log(w)) + 1;
    return { w, bits, len1, len2, len: len1 + len2, sigBytes: (len1 + len2) * 32, pkBytes: (len1 + len2) * 32 };
  }

  function _chain(x, start, steps) {
    let cur = x;
    for (let i = start; i < start + steps; i++) cur = K.keccak256(cur);
    return cur;
  }

  // base-w digits of the digest plus the checksum digits, big-endian.
  function wotsDigits(msgHash, w) {
    const m = need32(msgHash, 'message digest');
    const p = wotsParams(w);
    const mask = w - 1;
    const digits = new Array(p.len);
    let checksum = 0;
    for (let i = 0; i < p.len1; i++) {
      const bitPos = i * p.bits;
      const bytePos = bitPos >> 3;
      const shift = 8 - p.bits - (bitPos & 7);
      digits[i] = (m[bytePos] >> shift) & mask;
      checksum += (w - 1) - digits[i];
    }
    for (let i = 0; i < p.len2; i++) {
      const shift = (p.len2 - 1 - i) * p.bits;
      digits[p.len1 + i] = (checksum >> shift) & mask;
    }
    return digits;
  }

  function wotsKeygen(seed, w, leafIndex) {
    const s = seedBytes(seed);
    const p = wotsParams(w);
    const tag = K.utf8Bytes('wots' + w);
    const leaf = new Uint8Array(4);
    const li = leafIndex || 0;
    leaf[0] = (li >>> 24) & 0xff;
    leaf[1] = (li >>> 16) & 0xff;
    leaf[2] = (li >>> 8) & 0xff;
    leaf[3] = li & 0xff;
    const idx = new Uint8Array(2);
    const sk = new Array(p.len);
    const pk = new Array(p.len);
    for (let i = 0; i < p.len; i++) {
      idx[0] = (i >>> 8) & 0xff;
      idx[1] = i & 0xff;
      sk[i] = K.keccak256(K.concatBytes(s, tag, leaf, idx));
      pk[i] = _chain(sk[i], 0, w - 1);
    }
    return { sk, pk, params: p };
  }

  function wotsSign(sk, w, msgHash) {
    const digits = wotsDigits(msgHash, w);
    return digits.map((d, i) => _chain(sk[i], 0, d));
  }

  function wotsVerify(pk, w, msgHash, sig) {
    const digits = wotsDigits(msgHash, w);
    const p = wotsParams(w);
    if (!Array.isArray(sig) || sig.length !== p.len) return false;
    if (!Array.isArray(pk) || pk.length !== p.len) return false;
    for (let i = 0; i < p.len; i++) {
      const piece = bytes32OrNull(sig[i]);
      const expect = bytes32OrNull(pk[i]);
      if (!piece || !expect) return false;
      const h = _chain(piece, digits[i], (w - 1) - digits[i]);
      if (!eq32(h, expect)) return false;
    }
    return true;
  }

  /*
   * The WOTS public key is a pure function of signature plus message:
   * each chain element verifies to its top from wherever the signature
   * leaves it. That is what lets a detached verifier recompute the
   * committed merkle leaf without ever seeing the keypair, the same
   * mechanism XMSS relies on.
   */
  function wotsPkFromSig(w, msgHash, sig) {
    const digits = wotsDigits(msgHash, w);
    const p = wotsParams(w);
    if (!Array.isArray(sig) || sig.length !== p.len) return null;
    if (!sig.every((x) => bytes32OrNull(x))) return null;
    return digits.map((d, i) => _chain(bytes32OrNull(sig[i]), d, (w - 1) - d));
  }

  function wotsLeafDigest(pk) {
    const flat = new Uint8Array(pk.length * 32);
    pk.forEach((p, j) => flat.set(p, j * 32));
    return K.keccak256(flat);
  }

  // ---- Merkle tree ---------------------------------------------------------
  //
  // Leaves are 32 byte digests. Odd nodes at a level are promoted by
  // duplicating the last node, which keeps proofs a fixed height and lets
  // tampering with a duplicated sibling be detected through the index.

  function merkleBuild(leaves) {
    if (!leaves.length) fail('EmptyTree');
    const layers = [leaves.map((l) => need32(l, 'leaf'))];
    while (layers[layers.length - 1].length > 1) {
      const prev = layers[layers.length - 1];
      const next = [];
      for (let i = 0; i < prev.length; i += 2) {
        const right = i + 1 < prev.length ? prev[i + 1] : prev[i];
        next.push(K.keccak256(K.concatBytes(prev[i], right)));
      }
      layers.push(next);
    }
    return { layers, root: layers[layers.length - 1][0], height: layers.length - 1 };
  }

  function merkleProof(tree, index) {
    if (!tree || !tree.layers || !tree.layers[0] ||
        !Number.isInteger(index) || index < 0 || index >= tree.layers[0].length) {
      fail('BadMerkleIndex', index);
    }
    const proof = [];
    let idx = index;
    for (let level = 0; level < tree.layers.length - 1; level++) {
      const nodes = tree.layers[level];
      const sibIdx = idx ^ 1;
      proof.push({
        sibling: nodes[sibIdx] || nodes[idx], // odd node duplicates itself
        right: (idx & 1) === 0                // sibling sits to the right
      });
      idx >>= 1;
    }
    return proof;
  }

  function merkleVerify(root, leaf, index, proof) {
    const r = need32(root, 'root');
    let cur;
    try {
      cur = need32(leaf, 'leaf');
    } catch (e) {
      return false;
    }
    if (!Array.isArray(proof) || proof.length > 32) return false;
    if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) return false;
    let idx = index;
    for (const step of proof) {
      let sib;
      try {
        sib = need32(step.sibling, 'sibling');
      } catch (e) {
        return false;
      }
      const expectRight = (idx & 1) === 0;
      if (step.right !== expectRight) return false;
      cur = expectRight
        ? K.keccak256(K.concatBytes(cur, sib))
        : K.keccak256(K.concatBytes(sib, cur));
      idx >>= 1;
    }
    if (idx !== 0) return false; // proof shallower than the claimed index
    if (cur.length !== r.length) return false;
    for (let i = 0; i < 32; i++) if (cur[i] !== r[i]) return false;
    return true;
  }

  // ---- HashWallet ----------------------------------------------------------
  //
  // Stateful hash signature wallet. Every signature consumes exactly one
  // merkle leaf. The used leaf bitmap is the double spend guard; nextLeaf
  // is a monotonic counter that can only move forward, mirroring XMSS.

  class HashWallet {
    constructor(opts) {
      const o = opts || {};
      this.height = o.height === undefined ? 3 : o.height;
      if (!Number.isInteger(this.height) || this.height < 1 || this.height > 12) {
        fail('BadTreeHeight', 'height must be 1..12');
      }
      this.w = o.w || 16;
      this.scheme = o.scheme || 'lamport';
      if (!['lamport', 'wots'].includes(this.scheme)) fail('BadScheme', this.scheme);
      if (this.scheme === 'wots') wotsParams(this.w); // validates w
      this.seed = seedBytes(o.seed === undefined ? K.keccak256(K.utf8Bytes('pq-payguard-demo-seed')) : o.seed);
      this.size = 1 << this.height;
      this.usedBitmap = new Uint8Array(this.size);
      this.nextLeaf = 0;
      this._leafCache = new Map();

      const leaves = new Array(this.size);
      for (let i = 0; i < this.size; i++) {
        if (this.scheme === 'lamport') {
          const { pk } = lamportKeygen(this.seed, i);
          leaves[i] = lamportPkDigest(pk);
        } else {
          leaves[i] = wotsLeafDigest(wotsKeygen(this.seed, this.w, i).pk);
        }
      }
      this.tree = merkleBuild(leaves);
      this.root = this.tree.root;
    }

    remaining() {
      return this.size - this.nextLeaf;
    }

    leafUsed(i) {
      return this.usedBitmap[i] === 1;
    }

    _otsSign(leafIndex, msgHash) {
      if (this.scheme === 'lamport') {
        const sk = _lamportSk(this.seed, leafIndex);
        return lamportSign(sk, msgHash);
      }
      const { sk } = wotsKeygen(this.seed, this.w, leafIndex);
      return wotsSign(sk, this.w, msgHash);
    }

    /*
     * Sign a 32 byte digest with leaf `index`. The guard is explicit:
     * a consumed leaf position, a position below the monotonic counter,
     * or a position past the tree all fail closed.
     */
    signWith(leafIndex, msgHash) {
      const i = Number(leafIndex);
      if (!Number.isInteger(i) || i < 0 || i >= this.size) fail('LeafOutOfBounds', i);
      if (this.usedBitmap[i] === 1) fail('LeafReused', i);
      if (i < this.nextLeaf) fail('LeafReused', 'monotonic counter at ' + this.nextLeaf);
      const sig = this._otsSign(i, msgHash);
      this.usedBitmap[i] = 1;
      if (i >= this.nextLeaf) this.nextLeaf = i + 1;
      return {
        leafIndex: i,
        scheme: this.scheme,
        w: this.scheme === 'wots' ? this.w : undefined,
        digest: K.bytesToHex(need32(msgHash, 'message digest')),
        sig,
        proof: merkleProof(this.tree, i)
      };
    }

    sign(msgHash) {
      if (this.nextLeaf >= this.size) fail('LeafExhausted', this.size);
      return this.signWith(this.nextLeaf, msgHash);
    }

    /*
     * Raw OTS sign that bypasses the leaf guard, for the reuse catastrophe
     * demonstration only. Real callers always go through signWith.
     */
    signUnguarded(leafIndex, msgHash) {
      return this._otsSign(leafIndex, msgHash);
    }

    leafPublicKey(leafIndex) {
      if (this.scheme === 'lamport') {
        return lamportPublicKey(_lamportSk(this.seed, leafIndex));
      }
      return wotsKeygen(this.seed, this.w, leafIndex).pk;
    }

    leafDigest(leafIndex) {
      return this.tree.layers[0][leafIndex];
    }

    verify(msgHash, bundle) {
      const b = bundle || {};
      const i = Number(b.leafIndex);
      if (!Number.isInteger(i) || i < 0 || i >= this.size) {
        return { ok: false, reason: 'leaf index out of bounds' };
      }
      const leaf = this.leafDigest(i);
      if (!merkleVerify(this.root, leaf, i, b.proof)) {
        return { ok: false, reason: 'merkle proof rejected' };
      }
      let ok;
      if ((b.scheme || this.scheme) === 'lamport') {
        ok = lamportVerify(this.leafPublicKey(i), msgHash, b.sig);
      } else {
        ok = wotsVerify(this.leafPublicKey(i), b.w || this.w, msgHash, b.sig);
      }
      return ok ? { ok: true } : { ok: false, reason: 'one time signature invalid' };
    }

    exportState() {
      return {
        height: this.height,
        scheme: this.scheme,
        w: this.scheme === 'wots' ? this.w : undefined,
        root: K.bytesToHex(this.root),
        nextLeaf: this.nextLeaf,
        usedBitmap: Array.from(this.usedBitmap)
      };
    }
  }

  /*
   * Detached bundle verification: given only a merkle root, a digest and a
   * {leafIndex, scheme, w, sig, proof, leafPk} bundle, decide validity.
   * WOTS bundles need no extra key material because the pk recomputes from
   * sig+msg. Lamport bundles must carry leafPk (512 hashes) since half of
   * every public pair is never revealed by a signature.
   */
  function verifyDetached(root, msgHash, bundle) {
    const b = bundle || {};
    const i = Number(b.leafIndex);
    if (!Number.isInteger(i) || i < 0) return { ok: false, reason: 'leaf index out of bounds' };
    const scheme = b.scheme || 'lamport';
    let leaf;
    if (scheme === 'wots') {
      const pk = wotsPkFromSig(b.w || 16, msgHash, b.sig);
      if (!pk) return { ok: false, reason: 'malformed wots signature' };
      leaf = wotsLeafDigest(pk);
    } else {
      const pk = b.leafPk;
      if (!Array.isArray(pk) || pk.length !== 256) return { ok: false, reason: 'lamport bundle missing leaf pk' };
      if (!lamportVerify(pk, msgHash, b.sig)) return { ok: false, reason: 'one time signature invalid' };
      leaf = lamportPkDigest(pk.map((pair) => pair.map((x) => need32(x, 'pk element'))));
    }
    let rootBytes;
    try {
      rootBytes = need32(root, 'root');
    } catch (e) {
      return { ok: false, reason: 'bad merkle root' };
    }
    try {
      if (!merkleVerify(rootBytes, leaf, i, b.proof)) {
        return { ok: false, reason: 'merkle proof rejected' };
      }
    } catch (e) {
      return { ok: false, reason: 'malformed proof' };
    }
    return { ok: true };
  }

  // ---- toy elliptic curve DLP ----------------------------------------------
  //
  // y^2 = x^3 + 2x + 3 over F_97. About a hundred points, so a classical
  // brute force solves the discrete log instantly. This is the classical
  // analogue of what Shor's algorithm does to secp256k1 at full scale, run
  // here as a labeled illustration for the attack playground.

  const TOY_P = 97;
  const TOY_A = 2;
  const TOY_B = 3;

  function _mod(n, m) {
    return ((n % m) + m) % m;
  }

  function _modInv(a, m) {
    let [t, nt, r, nr] = [0, 1, m, _mod(a, m)];
    while (nr !== 0) {
      const q = Math.floor(r / nr);
      [t, nt] = [nt, t - q * nt];
      [r, nr] = [nr, r - q * nr];
    }
    if (r !== 1) fail('NoInverse');
    return _mod(t, m);
  }

  function toyPointAdd(P, Q) {
    if (P === null) return Q;
    if (Q === null) return P;
    const [x1, y1] = P;
    const [x2, y2] = Q;
    if (x1 === x2 && _mod(y1 + y2, TOY_P) === 0) return null;
    let lam;
    if (x1 === x2 && y1 === y2) {
      lam = _mod((3 * x1 * x1 + TOY_A) * _modInv(2 * y1, TOY_P), TOY_P);
    } else {
      lam = _mod((y2 - y1) * _modInv(x2 - x1, TOY_P), TOY_P);
    }
    const x3 = _mod(lam * lam - x1 - x2, TOY_P);
    const y3 = _mod(lam * (x1 - x3) - y1, TOY_P);
    return [x3, y3];
  }

  function toyScalarMul(k, P) {
    let R = null;
    let Q = P;
    let n = k;
    while (n > 0) {
      if (n & 1) R = toyPointAdd(R, Q);
      Q = toyPointAdd(Q, Q);
      n >>= 1;
    }
    return R;
  }

  // First curve point with the smallest x, found by scanning. Deterministic.
  function toyBasePoint() {
    for (let x = 0; x < TOY_P; x++) {
      const rhs = _mod(x * x * x + TOY_A * x + TOY_B, TOY_P);
      for (let y = 0; y < TOY_P; y++) {
        if (_mod(y * y, TOY_P) === rhs) return [x, y];
      }
    }
    fail('NoCurvePoint');
  }

  // Brute force discrete log: find d with d*G = Q. Bound keeps it instant.
  function toyDlpSolve(G, Q, bound) {
    const lim = bound || 8 * TOY_P;
    let R = null;
    for (let d = 0; d < lim; d++) {
      if (R !== null && R[0] === Q[0] && R[1] === Q[1]) return d;
      R = toyPointAdd(R, G);
    }
    return null;
  }

  return {
    PqError,
    digestBit,
    LAMPORT_SK_BYTES,
    LAMPORT_SIG_BYTES,
    LAMPORT_PK_BYTES,
    lamportKeygen,
    lamportPublicKey,
    lamportSign,
    lamportVerify,
    lamportPkDigest,
    lamportForge,
    lamportForgeMulti,
    wotsParams,
    wotsDigits,
    wotsKeygen,
    wotsSign,
    wotsVerify,
    wotsPkFromSig,
    wotsLeafDigest,
    verifyDetached,
    merkleBuild,
    merkleProof,
    merkleVerify,
    HashWallet,
    TOY_P,
    toyPointAdd,
    toyScalarMul,
    toyBasePoint,
    toyDlpSolve
  };
}));
