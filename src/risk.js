/*
 * Deterministic quantum exposure scoring for payment routes.
 *
 * The model is additive and transparent: a base score per signature scheme
 * reflects estimated Shor or Grover exposure, then modifiers add for a public
 * key already revealed on chain, value at risk, key age, and a deprecated
 * scheme flag. The result clamps to 0-100 and maps to the same four tiers the
 * PQPayGuardEscrow contract enforces: 0-29 low, 30-59 medium, 60-84 high,
 * 85-100 critical.
 *
 * This is an educational model. It is not a certified cryptanalysis and the
 * contract does not perform post quantum signatures; the score is a routing
 * signal, not a security guarantee.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.risk = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SCORE_LOW_MAX = 29;
  const SCORE_MEDIUM_MAX = 59;
  const SCORE_HIGH_MAX = 84;
  const SCORE_CRITICAL_MAX = 100;

  // Base exposure per scheme family, estimated quantum attack surface.
  const SCHEME_BASE = Object.freeze({
    'secp256k1': 55,
    'ecdsa-p256': 55,
    'ed25519': 45,
    'sr25519': 50,
    'rsa-2048': 70,
    'rsa-3072': 55,
    'x25519': 45,
    'falcon-512': 10,
    'ml-dsa-44': 8,
    'ml-dsa-65': 6,
    'ml-dsa-87': 4,
    'slh-dsa-128s': 4,
    'slh-dsa-192s': 3,
    'slh-dsa-256s': 2,
    'hash-only': 5
  });

  const MODIFIERS = Object.freeze({
    keyRevealed: 20,     // public key already visible on chain
    deprecated: 10,      // scheme flagged deprecated by policy
    value100: 4,         // route value >= 100 tUSD8
    value1000: 8,        // route value >= 1000 tUSD8 (replaces lower step)
    value10000: 15,      // route value >= 10000 tUSD8 (replaces lower step)
    age365: 5            // key older than 365 days
  });

  function scoreToTier(score) {
    if (!Number.isInteger(score) || score < 0 || score > SCORE_CRITICAL_MAX) {
      throw new RangeError('score must be an integer in 0..100: ' + score);
    }
    if (score <= SCORE_LOW_MAX) return 0;
    if (score <= SCORE_MEDIUM_MAX) return 1;
    if (score <= SCORE_HIGH_MAX) return 2;
    return 3;
  }

  function tierName(tier) {
    return ['low', 'medium', 'high', 'critical'][tier];
  }

  /*
   * input: {
   *   scheme: string key of SCHEME_BASE
   *   keyRevealed: bool
   *   deprecated: bool
   *   valueTusd: number (human units, not raw)
   *   ageDays: number
   * }
   * returns { score, tier, tierName, factors: [{label, points}] }
   */
  function exposureScore(input) {
    const i = input || {};
    const scheme = String(i.scheme || 'secp256k1');
    if (!Object.prototype.hasOwnProperty.call(SCHEME_BASE, scheme)) {
      throw new TypeError('unknown scheme: ' + scheme);
    }
    const factors = [{ label: 'base ' + scheme, points: SCHEME_BASE[scheme] }];
    let score = SCHEME_BASE[scheme];

    if (i.keyRevealed) {
      score += MODIFIERS.keyRevealed;
      factors.push({ label: 'public key already revealed', points: MODIFIERS.keyRevealed });
    }
    if (i.deprecated) {
      score += MODIFIERS.deprecated;
      factors.push({ label: 'deprecated scheme', points: MODIFIERS.deprecated });
    }
    const value = i.valueTusd === undefined || i.valueTusd === null
      ? 0 : Number(i.valueTusd);
    if (!Number.isFinite(value) || value < 0) throw new TypeError('bad valueTusd');
    if (value >= 10000) {
      score += MODIFIERS.value10000;
      factors.push({ label: 'value >= 10000 tUSD8', points: MODIFIERS.value10000 });
    } else if (value >= 1000) {
      score += MODIFIERS.value1000;
      factors.push({ label: 'value >= 1000 tUSD8', points: MODIFIERS.value1000 });
    } else if (value >= 100) {
      score += MODIFIERS.value100;
      factors.push({ label: 'value >= 100 tUSD8', points: MODIFIERS.value100 });
    }
    const age = i.ageDays === undefined || i.ageDays === null
      ? 0 : Number(i.ageDays);
    if (!Number.isFinite(age) || age < 0) throw new TypeError('bad ageDays');
    if (age > 365) {
      score += MODIFIERS.age365;
      factors.push({ label: 'key older than 365 days', points: MODIFIERS.age365 });
    }

    if (score > SCORE_CRITICAL_MAX) score = SCORE_CRITICAL_MAX;
    const tier = scoreToTier(score);
    return { score, tier, tierName: tierName(tier), scheme, factors };
  }

  return {
    SCORE_LOW_MAX,
    SCORE_MEDIUM_MAX,
    SCORE_HIGH_MAX,
    SCORE_CRITICAL_MAX,
    SCHEME_BASE,
    MODIFIERS,
    scoreToTier,
    tierName,
    exposureScore
  };
}));
