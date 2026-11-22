/*
 * EIP-1193 wallet helpers for QDay Aevum (chain 0xabe5). All functions take
 * the provider as an argument so they are trivially mockable in tests; the UI
 * passes window.ethereum when present.
 */
(function (root, factory) {
  let CH;
  if (typeof module === 'object' && module.exports) {
    CH = require('./chain.js');
  } else {
    CH = root.PQPG.chain;
  }
  const api = factory(CH);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.wallet = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (CH) {
  'use strict';

  const NETWORK = CH.NETWORK;

  function buildAddChainParams() {
    return {
      chainId: NETWORK.chainIdHex,
      chainName: NETWORK.name,
      rpcUrls: [NETWORK.rpcUrl],
      nativeCurrency: {
        name: NETWORK.nativeCurrency.name,
        symbol: NETWORK.nativeCurrency.symbol,
        decimals: NETWORK.nativeCurrency.decimals
      },
      blockExplorerUrls: [NETWORK.explorerUrl]
    };
  }

  function getProvider(candidate) {
    const p = candidate || (typeof window !== 'undefined' ? window.ethereum : null);
    if (!p || typeof p.request !== 'function') {
      throw new Error('no EIP-1193 provider found');
    }
    return p;
  }

  async function connectWallet(provider) {
    const p = getProvider(provider);
    const accounts = await p.request({ method: 'eth_requestAccounts' });
    const chainId = await p.request({ method: 'eth_chainId' });
    return {
      account: accounts && accounts[0] ? accounts[0] : null,
      accounts: accounts || [],
      chainId,
      chainIdNumber: Number(BigInt(chainId)),
      onAevum: Number(BigInt(chainId)) === NETWORK.chainId
    };
  }

  /*
   * Switch to Aevum; if the wallet does not know the chain (error 4902) it is
   * added with the official parameters first.
   */
  async function ensureAevumNetwork(provider) {
    const p = getProvider(provider);
    try {
      await p.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: NETWORK.chainIdHex }]
      });
      return { switched: true, added: false };
    } catch (err) {
      const code = err && (err.code === undefined ? null : err.code);
      if (code !== 4902) throw err;
      await p.request({
        method: 'wallet_addEthereumChain',
        params: [buildAddChainParams()]
      });
      return { switched: true, added: true };
    }
  }

  async function sendTransaction(provider, tx) {
    const p = getProvider(provider);
    return p.request({ method: 'eth_sendTransaction', params: [tx] });
  }

  return {
    buildAddChainParams,
    getProvider,
    connectWallet,
    ensureAevumNetwork,
    sendTransaction
  };
}));
