/*
 * Attestation and commitment hashing for PQ PayGuard.
 *
 * attestationHash: domain separated SHA-256 over a canonical JSON body that
 * records the computed risk score, the scoring factors and the payment
 * context. Produced off chain; the contract stores it in the escrow record.
 *
 * commitmentHash: keccak256 over the exact abi.encode the contract performs
 * in computeCommitment:
 *   keccak256(abi.encode(
 *     chainId, escrowContract, sessionId, payer, recipient,
 *     amount, riskScore, attestationHash, deadline))
 *
 * Because the contract recomputes this on chain, the score stored in the
 * escrow is provably the score inside the commitment. A caller cannot lower
 * the score to pick a faster release path.
 */
(function (root, factory) {
  let K, A;
  if (typeof module === 'object' && module.exports) {
    K = require('./keccak.js');
    A = require('./abi.js');
  } else {
    K = root.PQPG.keccak;
    A = root.PQPG.abi;
  }
  const api = factory(K, A);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.commit = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (K, A) {
  'use strict';

  const COMMITMENT_TYPES = Object.freeze([
    'uint256', 'address', 'uint256', 'address', 'address',
    'uint256', 'uint8', 'bytes32', 'uint64'
  ]);

  const ATTESTATION_DOMAIN = 'pq-payguard-attestation:';

  // Deterministic JSON: sorted keys, compact separators, no undefined fields.
  function canonicalString(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonicalString).join(',') + ']';
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalString(value[k])).join(',') + '}';
  }

  /*
   * Build the risk attestation body and its domain separated hash.
   * input: { payer, recipient, amountRaw, score, tier, scheme, factors,
   *          sessionId, nonce, issuedAt }
   * returns { body, attestationHash } where attestationHash is 0x prefixed.
   */
  async function buildAttestation(input) {
    const i = input || {};
    const body = {
      payer: String(i.payer).toLowerCase(),
      recipient: String(i.recipient).toLowerCase(),
      amountRaw: String(i.amountRaw),
      score: i.score,
      tier: i.tier,
      scheme: i.scheme,
      factors: (i.factors || []).map((f) => ({ label: String(f.label), points: Number(f.points) })),
      sessionId: String(i.sessionId),
      nonce: String(i.nonce || '0'),
      issuedAt: Number(i.issuedAt || 0)
    };
    const digest = await K.sha256(K.utf8Bytes(ATTESTATION_DOMAIN + canonicalString(body)));
    return { body, attestationHash: '0x' + K.bytesToHex(digest) };
  }

  /*
   * The exact commitment the contract recomputes. All arguments mirror
   * createEscrow parameters; contractAddress is the escrow deployment.
   */
  function computeCommitment(input) {
    const i = input || {};
    const encoded = A.encodeArgs(COMMITMENT_TYPES, [
      BigInt(i.chainId),
      String(i.contractAddress).toLowerCase(),
      BigInt(i.sessionId),
      String(i.payer).toLowerCase(),
      String(i.recipient).toLowerCase(),
      BigInt(i.amountRaw),
      BigInt(i.riskScore),
      String(i.attestationHash).toLowerCase(),
      BigInt(i.deadline)
    ]);
    return '0x' + K.bytesToHex(K.keccak256(K.hexToBytes(encoded)));
  }

  function verifyCommitment(expected, input) {
    return computeCommitment(input) === String(expected).toLowerCase();
  }

  return {
    COMMITMENT_TYPES,
    ATTESTATION_DOMAIN,
    canonicalString,
    buildAttestation,
    computeCommitment,
    verifyCommitment
  };
}));
