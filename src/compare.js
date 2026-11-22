/*
 * Signature scheme trade-off comparator and key budget planner.
 *
 * Deterministic, documented cost model. Sizes for the classical and NIST
 * standardized schemes are the published constants (FIPS 204 ML-DSA,
 * FIPS 205 SLH-DSA, Falcon, SEC 2 secp256k1, RFC 8032 Ed25519). The hash
 * based rows are computed from the actual Lamport and WOTS constructions
 * in pqsig.js, so the numbers the page shows are the same numbers the
 * code produces.
 *
 * Gas model (documented, not an emulator):
 *   calldata   : 16 gas per nonzero byte, 4 per zero byte (EIP-2028).
 *                Typical estimate assumes ~6% zero bytes.
 *   keccak256  : 30 gas + 6 per 32-byte word. Lamport verify hashes a
 *                32-byte preimage (1 word, 36 gas); a merkle node hashes
 *                a 64-byte pair (2 words, 42 gas).
 *   ecrecover  : 3000 gas fixed precompile.
 *   NIST PQC   : no EVM precompile; marked off-chain verify only.
 */
(function (root, factory) {
  let PQ;
  if (typeof module === 'object' && module.exports) {
    PQ = require('./pqsig.js');
  } else {
    PQ = root.PQPG.pqsig;
  }
  const api = factory(PQ);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.compare = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (PQ) {
  'use strict';

  const GAS = Object.freeze({
    TX_BASE: 21000,
    CALLDATA_NONZERO: 16,
    CALLDATA_ZERO: 4,
    KECCAK_BASE: 30,
    KECCAK_WORD: 6,
    ECRECOVER: 3000,
    // typical share of zero bytes in random looking signature data
    ZERO_BYTE_SHARE: 0.06
  });

  function keccakGas(inputBytes) {
    return GAS.KECCAK_BASE + GAS.KECCAK_WORD * Math.ceil(inputBytes / 32);
  }

  function calldataGas(bytes, zeroBytes) {
    const z = zeroBytes === undefined ? Math.round(bytes * GAS.ZERO_BYTE_SHARE) : zeroBytes;
    return z * GAS.CALLDATA_ZERO + (bytes - z) * GAS.CALLDATA_NONZERO;
  }

  // ---- scheme table --------------------------------------------------------

  /*
   * One row per scheme. hashOpsVerify counts keccak calls a verifier would
   * make; null where the scheme is not hash-verified in EVM terms.
   * onchainGas is the deterministic model total for a single verify
   * (base tx + calldata + execution), or null when the scheme has no
   * practical on-chain verify path today.
   */
  function schemeRows(merkleHeight) {
    const H = merkleHeight === undefined ? 0 : merkleHeight;
    const proofBytes = H * 32;
    const rows = [];

    // Lamport-256 OTS (this repo's construction).
    {
      const hashOps = 256 + H;
      const exec = hashOps === 0 ? 0 : 256 * keccakGas(32) + H * keccakGas(64);
      const cdBytes = PQ.LAMPORT_SIG_BYTES + proofBytes;
      rows.push({
        id: 'lamport-256',
        name: 'Lamport-256 OTS',
        family: 'hash',
        sigBytes: PQ.LAMPORT_SIG_BYTES,
        pkBytes: PQ.LAMPORT_PK_BYTES,
        proofBytes,
        totalBytes: cdBytes + 136, // plus createEscrow-style arg overhead
        hashOpsVerify: hashOps,
        execGas: exec,
        calldataBytes: cdBytes,
        calldataGas: calldataGas(cdBytes),
        onchainGas: GAS.TX_BASE + calldataGas(cdBytes) + exec,
        pqSecure: true,
        oneTime: true
      });
    }

    // WOTS rows for each RFC 8391 parameter.
    for (const w of [4, 16, 256]) {
      const p = PQ.wotsParams(w);
      // average chain work at verify: (w - 1)/2 steps per chain
      const avgSteps = p.len * (w - 1) / 2;
      const exec = Math.round(avgSteps) * keccakGas(32) + H * keccakGas(64);
      const cdBytes = p.sigBytes + proofBytes;
      rows.push({
        id: 'wots-w' + w,
        name: 'WOTS w=' + w,
        family: 'hash',
        w,
        chains: p.len,
        sigBytes: p.sigBytes,
        pkBytes: p.pkBytes,
        proofBytes,
        totalBytes: cdBytes + 136,
        hashOpsVerify: Math.round(avgSteps) + H,
        execGas: exec,
        calldataBytes: cdBytes,
        calldataGas: calldataGas(cdBytes),
        onchainGas: GAS.TX_BASE + calldataGas(cdBytes) + exec,
        pqSecure: true,
        oneTime: true
      });
    }

    // Classical schemes and NIST standardized PQC, published sizes.
    const fixed = [
      { id: 'secp256k1', name: 'ECDSA secp256k1', family: 'classical', sigBytes: 65, pkBytes: 33,
        exec: GAS.ECRECOVER, hashOps: 0, pq: false, note: 'ecrecover precompile; broken by Shor' },
      { id: 'ed25519', name: 'Ed25519', family: 'classical', sigBytes: 64, pkBytes: 32,
        exec: null, hashOps: 0, pq: false, note: 'no EVM precompile; broken by Shor' },
      { id: 'rsa-2048', name: 'RSA-2048', family: 'classical', sigBytes: 256, pkBytes: 256,
        exec: null, hashOps: 0, pq: false, note: 'broken by Shor' },
      { id: 'falcon-512', name: 'Falcon-512', family: 'nist-pqc', sigBytes: 666, pkBytes: 897,
        exec: null, hashOps: null, pq: true, note: 'FIPS 204 fn-dsa track, avg sig size' },
      { id: 'ml-dsa-44', name: 'ML-DSA-44', family: 'nist-pqc', sigBytes: 2420, pkBytes: 1312,
        exec: null, hashOps: null, pq: true, note: 'FIPS 204' },
      { id: 'ml-dsa-65', name: 'ML-DSA-65', family: 'nist-pqc', sigBytes: 3309, pkBytes: 1952,
        exec: null, hashOps: null, pq: true, note: 'FIPS 204' },
      { id: 'ml-dsa-87', name: 'ML-DSA-87', family: 'nist-pqc', sigBytes: 4627, pkBytes: 2592,
        exec: null, hashOps: null, pq: true, note: 'FIPS 204' },
      { id: 'slh-dsa-128s', name: 'SLH-DSA-128s', family: 'nist-pqc', sigBytes: 7856, pkBytes: 32,
        exec: null, hashOps: null, pq: true, note: 'FIPS 205, hash based, stateless' },
      { id: 'slh-dsa-128f', name: 'SLH-DSA-128f', family: 'nist-pqc', sigBytes: 17088, pkBytes: 32,
        exec: null, hashOps: null, pq: true, note: 'FIPS 205, fast variant' }
    ];
    for (const f of fixed) {
      const cdBytes = f.sigBytes;
      const exec = f.exec;
      rows.push({
        id: f.id,
        name: f.name,
        family: f.family,
        sigBytes: f.sigBytes,
        pkBytes: f.pkBytes,
        proofBytes: 0,
        totalBytes: cdBytes + 136,
        hashOpsVerify: f.hashOps,
        execGas: exec,
        calldataBytes: cdBytes,
        calldataGas: calldataGas(cdBytes),
        onchainGas: exec === null ? null : GAS.TX_BASE + calldataGas(cdBytes) + exec,
        pqSecure: f.pq,
        oneTime: false,
        note: f.note
      });
    }
    return rows;
  }

  // ---- key budget planner ----------------------------------------------------

  /*
   * A stateful hash wallet holds 2^H one time leaves. Given how many are
   * already consumed and the signing rate, compute what remains, how long
   * it lasts and when rotation is due.
   * level: 'ok' | 'warn' (>=75% used) | 'critical' (>=90%) | 'exhausted'
   */
  function keyBudget(height, used, signsPerDay) {
    const total = 2 ** height;
    if (!Number.isInteger(used) || used < 0 || used > total) {
      throw new RangeError('used leaves out of range: ' + used);
    }
    const remaining = total - used;
    const pct = used / total;
    let level = 'ok';
    if (remaining === 0) level = 'exhausted';
    else if (pct >= 0.9) level = 'critical';
    else if (pct >= 0.75) level = 'warn';
    const rate = Number(signsPerDay);
    const daysLeft = rate > 0 ? remaining / rate : Infinity;
    return {
      height,
      total,
      used,
      remaining,
      pctUsed: Math.round(pct * 1000) / 10,
      level,
      rotateNow: level === 'critical' || level === 'exhausted',
      daysLeft: daysLeft === Infinity ? null : Math.round(daysLeft * 10) / 10,
      signsPerDay: rate > 0 ? rate : null
    };
  }

  // Max safe signatures before rotation is recommended for a tree height.
  function capacityForHeight(height) {
    const total = 2 ** height;
    return {
      height,
      total,
      warnAt: Math.floor(total * 0.75),
      criticalAt: Math.floor(total * 0.9),
      proofBytes: height * 32,
      sigBytesLamport: PQ.LAMPORT_SIG_BYTES + height * 32
    };
  }

  return { GAS, keccakGas, calldataGas, schemeRows, keyBudget, capacityForHeight };
}));
