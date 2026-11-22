/*
 * Read-only JSON-RPC client for the QDay Aevum testnet with a deterministic
 * offline fallback. Nothing here runs on page load; the UI calls probeTestnet
 * only from an explicit button press.
 */
(function (root, factory) {
  let K, A, CH;
  if (typeof module === 'object' && module.exports) {
    K = require('./keccak.js');
    A = require('./abi.js');
    CH = require('./chain.js');
  } else {
    K = root.PQPG.keccak;
    A = root.PQPG.abi;
    CH = root.PQPG.chain;
  }
  const api = factory(K, A, CH);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.rpc = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (K, A, CH) {
  'use strict';

  const NETWORK = CH.NETWORK;
  const TUSD8 = CH.TUSD8;

  async function rpcCall(method, params, opts) {
    opts = opts || {};
    const fetchFn = opts.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!fetchFn) throw new Error('fetch is unavailable in this environment');
    const rpcUrl = opts.rpcUrl || NETWORK.rpcUrl;
    const timeoutMs = opts.timeoutMs || 8000;

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
      const res = await fetchFn(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: opts.id || 1, method, params: params || [] }),
        signal: controller ? controller.signal : undefined
      });
      if (!res || !res.ok) throw new Error('RPC HTTP status ' + (res ? res.status : 'unknown'));
      const data = await res.json();
      if (data.error) throw new Error('RPC error ' + data.error.code + ': ' + data.error.message);
      if (data.result === undefined) throw new Error('RPC response missing result');
      return data.result;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  function encodeSymbol() { return A.encodeCall(CH.TOKEN_ABI.symbol, []); }
  function encodeDecimals() { return A.encodeCall(CH.TOKEN_ABI.decimals, []); }
  function encodeTotalSupply() { return A.encodeCall(CH.TOKEN_ABI.totalSupply, []); }
  function encodeBalanceOf(account) { return A.encodeCall(CH.TOKEN_ABI.balanceOf, [account]); }
  function encodeNextEscrowId() { return A.encodeCall(CH.ESCROW_ABI.nextEscrowId, []); }
  function encodeReleaseBlocker(escrowId) { return A.encodeCall(CH.ESCROW_ABI.releaseBlocker, [BigInt(escrowId)]); }

  function simulateTestnetProbe(options) {
    const opts = options || {};
    const seed = K.keccak256(K.utf8Bytes('pqpg-sim:' + (opts.account || 'none')));
    const blockNumber = 3626704 + (((seed[0] << 8) | seed[1]) % 4096);
    const supply = 3227400n * 1000000n;
    const balance = opts.account ? (250n + BigInt(seed[2])) * 1000000n : null;
    return {
      mode: 'simulation',
      live: false,
      fallbackReason: opts.fallbackReason || 'offline deterministic simulation',
      rpcUrl: opts.rpcUrl || NETWORK.rpcUrl,
      chainId: NETWORK.chainId,
      chainIdHex: NETWORK.chainIdHex,
      chainIdMatches: true,
      blockNumber,
      blockNumberHex: '0x' + blockNumber.toString(16),
      token: {
        address: TUSD8.address,
        symbol: TUSD8.symbol,
        decimals: TUSD8.decimals,
        totalSupplyRaw: supply.toString(),
        totalSupplyFormatted: CH.formatTokenUnits(supply, TUSD8.decimals)
      },
      account: opts.account || null,
      accountBalanceRaw: balance ? balance.toString() : null,
      accountBalanceFormatted: balance ? CH.formatTokenUnits(balance, TUSD8.decimals) : null
    };
  }

  /*
   * Live probe of chain id, block number and the official tUSD8 contract.
   * Any failure degrades to the deterministic simulation, marked with
   * live:false and a human readable fallbackReason.
   */
  async function probeTestnet(options) {
    const opts = options || {};
    const account = opts.account && CH.isValidAddress(opts.account)
      ? CH.normalizeAddress(opts.account) : null;
    try {
      const base = { fetch: opts.fetch, rpcUrl: opts.rpcUrl, timeoutMs: opts.timeoutMs };
      const call = (method, params, id) =>
        rpcCall(method, params, Object.assign({ id }, base));
      const [chainHex, blockHex, symHex, decHex, supHex] = await Promise.all([
        call('eth_chainId', [], 1),
        call('eth_blockNumber', [], 2),
        call('eth_call', [{ to: TUSD8.address, data: encodeSymbol() }, 'latest'], 3),
        call('eth_call', [{ to: TUSD8.address, data: encodeDecimals() }, 'latest'], 4),
        call('eth_call', [{ to: TUSD8.address, data: encodeTotalSupply() }, 'latest'], 5)
      ]);

      const chainId = Number(BigInt(chainHex));
      const decimals = Number(A.decodeArgs(['uint8'], decHex)[0]);
      const totalSupplyRaw = A.decodeArgs(['uint256'], supHex)[0];
      let accountBalanceRaw = null;
      let accountBalanceFormatted = null;
      if (account) {
        const balHex = await call(
          'eth_call',
          [{ to: TUSD8.address, data: encodeBalanceOf(account) }, 'latest'], 6);
        const bal = A.decodeArgs(['uint256'], balHex)[0];
        accountBalanceRaw = bal.toString();
        accountBalanceFormatted = CH.formatTokenUnits(bal, decimals);
      }

      return {
        mode: 'live',
        live: true,
        fallbackReason: null,
        rpcUrl: opts.rpcUrl || NETWORK.rpcUrl,
        chainId,
        chainIdHex: '0x' + chainId.toString(16),
        chainIdMatches: chainId === NETWORK.chainId,
        blockNumber: Number(BigInt(blockHex)),
        blockNumberHex: blockHex,
        token: {
          address: TUSD8.address,
          symbol: A.decodeArgs(['string'], symHex)[0],
          decimals,
          totalSupplyRaw: totalSupplyRaw.toString(),
          totalSupplyFormatted: CH.formatTokenUnits(totalSupplyRaw, decimals)
        },
        account,
        accountBalanceRaw,
        accountBalanceFormatted
      };
    } catch (err) {
      return simulateTestnetProbe({
        account,
        rpcUrl: opts.rpcUrl,
        fallbackReason: err && err.message ? err.message : String(err)
      });
    }
  }

  // Read nextEscrowId + releaseBlocker off a deployed escrow (opt-in reads).
  async function readEscrowCount(contractAddress, opts) {
    opts = opts || {};
    const hex = await rpcCall('eth_call',
      [{ to: contractAddress, data: encodeNextEscrowId() }, 'latest'],
      Object.assign({ id: 7 }, opts));
    return A.decodeArgs(['uint256'], hex)[0];
  }

  async function readReleaseBlocker(contractAddress, escrowId, opts) {
    opts = opts || {};
    const hex = await rpcCall('eth_call',
      [{ to: contractAddress, data: encodeReleaseBlocker(escrowId) }, 'latest'],
      Object.assign({ id: 8 }, opts));
    const w = A.decodeArgs(['bytes32'], hex)[0];
    return K.hexToBytes(w).reduce((s, b) => s + (b ? String.fromCharCode(b) : ''), '');
  }

  const SESSION_TYPES = Object.freeze([
    'address', 'address', 'address',
    'uint256', 'uint256', 'uint256',
    'uint64', 'uint64', 'uint64',
    'bool', 'bool'
  ]);

  const ESCROW_TYPES = Object.freeze([
    'uint256', 'address', 'address', 'uint256',
    'uint8', 'uint8', 'uint8', 'bool',
    'bytes32', 'bytes32',
    'uint64', 'uint64', 'uint64'
  ]);

  // Decode getSession(uint256) into a plain object.
  async function readSession(contractAddress, sessionId, opts) {
    opts = opts || {};
    const hex = await rpcCall('eth_call',
      [{ to: contractAddress, data: A.encodeCall(CH.ESCROW_ABI.getSession, [BigInt(sessionId)]) }, 'latest'],
      Object.assign({ id: 9 }, opts));
    const v = A.decodeArgs(SESSION_TYPES, hex);
    return {
      payer: v[0], operator: v[1], guardian: v[2],
      maxPerTx: v[3], capTotal: v[4], spent: v[5],
      expiry: Number(v[6]), mediumDelay: Number(v[7]), highDelay: Number(v[8]),
      paused: v[9], revoked: v[10]
    };
  }

  // Decode getEscrow(uint256) into a plain object. tier/status are returned
  // as their enum ordinals; CH.TIER_NAMES / CH.STATUS_NAMES map them.
  async function readEscrow(contractAddress, escrowId, opts) {
    opts = opts || {};
    const hex = await rpcCall('eth_call',
      [{ to: contractAddress, data: A.encodeCall(CH.ESCROW_ABI.getEscrow, [BigInt(escrowId)]) }, 'latest'],
      Object.assign({ id: 10 }, opts));
    const v = A.decodeArgs(ESCROW_TYPES, hex);
    return {
      sessionId: v[0], payer: v[1], recipient: v[2], amount: v[3],
      riskScore: Number(v[4]), tier: Number(v[5]), status: Number(v[6]),
      guardianApproved: v[7],
      attestationHash: v[8], commitmentHash: v[9],
      createdAt: Number(v[10]), deadline: Number(v[11]), releaseNotBefore: Number(v[12])
    };
  }

  return {
    rpcCall,
    encodeSymbol,
    encodeDecimals,
    encodeTotalSupply,
    encodeBalanceOf,
    encodeNextEscrowId,
    encodeReleaseBlocker,
    simulateTestnetProbe,
    probeTestnet,
    readEscrowCount,
    readReleaseBlocker,
    readSession,
    readEscrow
  };
}));
