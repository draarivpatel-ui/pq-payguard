/*
 * QDay Aevum testnet constants and value helpers.
 *
 * Every network parameter below comes from https://qday.io/official-links.
 * tUSD8 is the official test stablecoin at 6 decimals on chain 44005.
 */
(function (root, factory) {
  let A = null;
  if (typeof module === 'object' && module.exports) {
    A = require('./abi.js');
  } else {
    A = root.PQPG && root.PQPG.abi;
  }
  const api = factory(A);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.chain = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (A) {
  'use strict';

  const NETWORK = Object.freeze({
    name: 'QDay Aevum Testnet',
    chainId: 44005,
    chainIdHex: '0xabe5',
    rpcUrl: 'https://rpc-test.qday.info',
    explorerUrl: 'https://explorer-test.qday.info',
    faucetUrl: 'https://faucet.qday.info/en',
    nativeCurrency: Object.freeze({
      name: 'QDay Testnet',
      symbol: 'tQDAY',
      decimals: 18
    })
  });

  const TUSD8 = Object.freeze({
    address: '0x456569838f1d43009A91ebA4263147Afd7233483',
    symbol: 'tUSD8',
    decimals: 6
  });

  const QDAY_FAUCET_CONTRACT = '0xE5074CBbd046AFb491EB8692abD6cF7ECCC6dEE5';

  // Function signatures on PQPayGuardEscrow, single source of truth for
  // calldata builders, decoders, tests and the deploy script.
  const ESCROW_ABI = Object.freeze({
    createSession: 'createSession(address,address,uint256,uint256,uint64,uint64,uint64)',
    setSessionPaused: 'setSessionPaused(uint256,bool)',
    revokeSession: 'revokeSession(uint256)',
    createEscrow: 'createEscrow(uint256,address,uint256,uint8,bytes32,bytes32,uint64)',
    guardianApprove: 'guardianApprove(uint256)',
    release: 'release(uint256)',
    revokeEscrow: 'revokeEscrow(uint256)',
    revokeEscrows: 'revokeEscrows(uint256[])',
    getSession: 'getSession(uint256)',
    getEscrow: 'getEscrow(uint256)',
    releaseBlocker: 'releaseBlocker(uint256)',
    computeCommitment: 'computeCommitment(uint256,address,address,uint256,uint8,bytes32,uint64)',
    tierOf: 'tierOf(uint8)',
    nextSessionId: 'nextSessionId()',
    nextEscrowId: 'nextEscrowId()',
    token: 'token()',
    scoreLowMax: 'SCORE_LOW_MAX()',
    scoreMediumMax: 'SCORE_MEDIUM_MAX()',
    scoreHighMax: 'SCORE_HIGH_MAX()',
    scoreCriticalMax: 'SCORE_CRITICAL_MAX()',
    maxDelay: 'MAX_DELAY()',
    maxBatchRevoke: 'MAX_BATCH_REVOKE()'
  });

  const TOKEN_ABI = Object.freeze({
    approve: 'approve(address,uint256)',
    transfer: 'transfer(address,uint256)',
    balanceOf: 'balanceOf(address)',
    allowance: 'allowance(address,address)',
    decimals: 'decimals()',
    symbol: 'symbol()',
    totalSupply: 'totalSupply()'
  });

  const TIER_NAMES = Object.freeze(['low', 'medium', 'high', 'critical']);
  const STATUS_NAMES = Object.freeze(['none', 'funded', 'released', 'revoked']);

  // ---- addresses -------------------------------------------------------

  function isValidAddress(addr) {
    return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr);
  }

  function normalizeAddress(addr) {
    if (!isValidAddress(addr)) throw new TypeError('invalid address: ' + addr);
    return '0x' + addr.slice(2).toLowerCase();
  }

  function sameAddress(a, b) {
    return isValidAddress(a) && isValidAddress(b) &&
      a.toLowerCase() === b.toLowerCase();
  }

  // ---- token units (6 decimals, exact BigInt math) ----------------------

  function parseTokenUnits(text, decimals) {
    const dec = decimals === undefined ? TUSD8.decimals : decimals;
    const s = String(text).trim();
    if (!/^\d+(\.\d+)?$/.test(s)) {
      throw new TypeError('amount must be a non-negative decimal number');
    }
    const dot = s.indexOf('.');
    const whole = dot === -1 ? s : s.slice(0, dot);
    const frac = dot === -1 ? '' : s.slice(dot + 1);
    if (frac.length > dec) {
      throw new TypeError('amount has more than ' + dec + ' decimal places');
    }
    return BigInt(whole) * (10n ** BigInt(dec)) +
      BigInt((frac + '0'.repeat(dec)).slice(0, dec) || '0');
  }

  function formatTokenUnits(raw, decimals) {
    const dec = decimals === undefined ? TUSD8.decimals : decimals;
    const neg = raw < 0n;
    const v = neg ? -raw : BigInt(raw);
    const base = 10n ** BigInt(dec);
    const whole = v / base;
    const frac = (v % base).toString().padStart(dec, '0').replace(/0+$/, '');
    return (neg ? '-' : '') + whole.toString() + (frac ? '.' + frac : '');
  }

  // ---- urls ------------------------------------------------------------

  function explorerTxUrl(hash) { return NETWORK.explorerUrl + '/tx/' + hash; }
  function explorerAddressUrl(addr) { return NETWORK.explorerUrl + '/address/' + addr; }
  function explorerTokenUrl(addr) { return NETWORK.explorerUrl + '/token/' + addr; }

  function shortHash(h, head, tail) {
    const s = String(h);
    const a = head === undefined ? 10 : head;
    const b = tail === undefined ? 8 : tail;
    return s.length <= a + b ? s : s.slice(0, a) + '...' + s.slice(-b);
  }

  // ---- calldata builders -----------------------------------------------
  // Thin wrappers over abi.encodeCall for the escrow + token surfaces.
  // All amounts are raw integer units (6 decimals), never floats.

  function needAbi() {
    if (!A) throw new Error('abi module unavailable');
    return A;
  }

  // expiry accepts an absolute unix time, or expiryOffset seconds from
  // `now` (defaults to the current time).
  function buildCreateSession(o) {
    const a = needAbi();
    const expiry = o.expiry !== undefined
      ? BigInt(o.expiry)
      : BigInt(o.now !== undefined ? o.now : Math.floor(Date.now() / 1000)) + BigInt(o.expiryOffset || 0);
    return a.encodeCall(ESCROW_ABI.createSession, [
      o.operator || '0x0000000000000000000000000000000000000000',
      o.guardian || '0x0000000000000000000000000000000000000000',
      BigInt(o.maxPerTxRaw),
      BigInt(o.capTotalRaw),
      expiry,
      BigInt(o.mediumDelay || 0),
      BigInt(o.highDelay || 0)
    ]);
  }

  function buildCreateEscrow(o) {
    const a = needAbi();
    return a.encodeCall(ESCROW_ABI.createEscrow, [
      BigInt(o.sessionId),
      o.recipient,
      BigInt(o.amountRaw),
      BigInt(o.riskScore),
      o.attestationHash,
      o.commitmentHash,
      BigInt(o.deadline)
    ]);
  }

  function buildRelease(escrowId) { return needAbi().encodeCall(ESCROW_ABI.release, [BigInt(escrowId)]); }
  function buildGuardianApprove(escrowId) { return needAbi().encodeCall(ESCROW_ABI.guardianApprove, [BigInt(escrowId)]); }
  function buildRevokeEscrow(escrowId) { return needAbi().encodeCall(ESCROW_ABI.revokeEscrow, [BigInt(escrowId)]); }
  function buildRevokeEscrows(escrowIds) {
    return needAbi().encodeCall(ESCROW_ABI.revokeEscrows, [(escrowIds || []).map((id) => BigInt(id))]);
  }
  function buildSetSessionPaused(sessionId, paused) {
    return needAbi().encodeCall(ESCROW_ABI.setSessionPaused, [BigInt(sessionId), !!paused]);
  }
  function buildRevokeSession(sessionId) { return needAbi().encodeCall(ESCROW_ABI.revokeSession, [BigInt(sessionId)]); }

  function buildApprove(spender, amountRaw) {
    return needAbi().encodeCall(TOKEN_ABI.approve, [spender, BigInt(amountRaw)]);
  }
  function buildTransfer(to, amountRaw) {
    return needAbi().encodeCall(TOKEN_ABI.transfer, [to, BigInt(amountRaw)]);
  }
  function buildMint(to, amountRaw) {
    return needAbi().encodeCall('mint(address,uint256)', [to, BigInt(amountRaw)]);
  }

  return {
    NETWORK,
    TUSD8,
    QDAY_FAUCET_CONTRACT,
    ESCROW_ABI,
    TOKEN_ABI,
    TIER_NAMES,
    STATUS_NAMES,
    isValidAddress,
    normalizeAddress,
    sameAddress,
    parseTokenUnits,
    formatTokenUnits,
    explorerTxUrl,
    explorerAddressUrl,
    explorerTokenUrl,
    shortHash,
    buildCreateSession,
    buildCreateEscrow,
    buildRelease,
    buildGuardianApprove,
    buildRevokeEscrow,
    buildRevokeEscrows,
    buildSetSessionPaused,
    buildRevokeSession,
    buildApprove,
    buildTransfer,
    buildMint
  };
}));
