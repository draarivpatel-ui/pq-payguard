'use strict';

/* RPC client and wallet helper tests with mocked transports. */

const test = require('node:test');
const assert = require('node:assert/strict');
const RPC = require('../src/rpc.js');
const W = require('../src/wallet.js');
const CH = require('../src/chain.js');

const ADDR = '0x0000000000000000000000000000000000000aa1';

function mockFetch(handlers) {
  const calls = [];
  return {
    calls,
    fetch: async (url, init) => {
      const body = JSON.parse(init.body);
      calls.push({ url, body });
      const handler = handlers[body.method];
      if (!handler) throw new Error('unexpected method ' + body.method);
      const result = typeof handler === 'function' ? handler(body) : handler;
      return {
        ok: true,
        json: async () => ({ jsonrpc: '2.0', id: body.id, result })
      };
    }
  };
}

const WORD = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');
const SYMBOL_RESP =
  '0x' + '20'.padStart(64, '0') + '5'.padStart(64, '0') +
  '7455534438'.padEnd(64, '0');

test('RPC 01: live probe decodes chain, block and token data', async () => {
  const m = mockFetch({
    eth_chainId: '0xabe5',
    eth_blockNumber: '0x375490',
    eth_call: (b) => {
      const data = b.params[0].data;
      if (data.startsWith('0x95d89b41')) return SYMBOL_RESP;       // symbol()
      if (data.startsWith('0x313ce567')) return WORD(6);            // decimals()
      if (data.startsWith('0x18160ddd')) return WORD(3227400000000n); // totalSupply()
      if (data.startsWith('0x70a08231')) return WORD(250000000n);   // balanceOf()
      throw new Error('bad call ' + data);
    }
  });
  const r = await RPC.probeTestnet({ account: ADDR, fetch: m.fetch });
  assert.equal(r.live, true);
  assert.equal(r.mode, 'live');
  assert.equal(r.chainId, 44005);
  assert.equal(r.chainIdMatches, true);
  assert.equal(r.blockNumber, 0x375490);
  assert.equal(r.token.symbol, 'tUSD8');
  assert.equal(r.token.decimals, 6);
  assert.equal(r.token.totalSupplyFormatted, '3227400');
  assert.equal(r.accountBalanceFormatted, '250');
  // 5 batched calls + 1 balance call
  assert.equal(m.calls.length, 6);
});

test('RPC 02: offline probe falls back to marked simulation', async () => {
  const m = mockFetch({ eth_chainId: () => { throw new Error('network down'); } });
  const r = await RPC.probeTestnet({ account: ADDR, fetch: m.fetch });
  assert.equal(r.live, false);
  assert.equal(r.mode, 'simulation');
  assert.equal(r.fallbackReason, 'network down');
  assert.equal(r.chainIdMatches, true);
});

test('RPC 03: http error and rpc error both degrade gracefully', async () => {
  const bad = { fetch: async () => ({ ok: false, status: 503, json: async () => ({}) }) };
  const r1 = await RPC.probeTestnet({ fetch: bad.fetch });
  assert.equal(r1.live, false);
  assert.match(r1.fallbackReason, /503/);

  const rpcErr = mockFetch({ eth_chainId: () => { const e = new Error('x'); throw e; } });
  const r2 = await RPC.probeTestnet({ fetch: rpcErr.fetch });
  assert.equal(r2.live, false);
});

test('RPC 04: rpcCall unwraps result and surfaces rpc errors', async () => {
  const m = mockFetch({ eth_chainId: '0xabe5' });
  assert.equal(await RPC.rpcCall('eth_chainId', [], { fetch: m.fetch }), '0xabe5');

  const errFetch = async (url, init) => ({
    ok: true,
    json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32000, message: 'reverted' } })
  });
  await assert.rejects(
    () => RPC.rpcCall('eth_call', [], { fetch: errFetch }),
    /reverted/
  );
});

test('RPC 05: readEscrowCount and readReleaseBlocker decode responses', async () => {
  const blockerWord = '0x' + Buffer.from('timelock').toString('hex').padEnd(64, '0');
  const m = mockFetch({
    eth_call: (b) => {
      if (b.params[0].data.startsWith('0x89cb29dd')) return WORD(3); // nextEscrowId
      return blockerWord;
    }
  });
  const c = await RPC.readEscrowCount('0x' + '11'.repeat(20), { fetch: m.fetch });
  assert.equal(c, 3n);
  const bl = await RPC.readReleaseBlocker('0x' + '11'.repeat(20), 2, { fetch: m.fetch });
  assert.equal(bl, 'timelock');
});

test('WALLET 01: buildAddChainParams carries official values', () => {
  const p = W.buildAddChainParams();
  assert.equal(p.chainId, '0xabe5');
  assert.equal(p.rpcUrls[0], 'https://rpc-test.qday.info');
  assert.equal(p.nativeCurrency.symbol, 'tQDAY');
  assert.equal(p.nativeCurrency.decimals, 18);
  assert.equal(p.blockExplorerUrls[0], 'https://explorer-test.qday.info');
});

test('WALLET 02: connectWallet reports chain state', async () => {
  const provider = {
    requests: [],
    request: async ({ method }) => {
      provider.requests.push(method);
      if (method === 'eth_requestAccounts') return [ADDR];
      if (method === 'eth_chainId') return '0xabe5';
      throw new Error('unexpected ' + method);
    }
  };
  const r = await W.connectWallet(provider);
  assert.equal(r.account, ADDR);
  assert.equal(r.chainIdNumber, 44005);
  assert.equal(r.onAevum, true);
});

test('WALLET 03: ensureAevumNetwork switches, or adds on 4902', async () => {
  const seen = [];
  const provider = {
    request: async ({ method, params }) => {
      seen.push(method);
      if (method === 'wallet_switchEthereumChain' && seen.length === 1) {
        const e = new Error('unknown chain'); e.code = 4902; throw e;
      }
      return null;
    }
  };
  const r = await W.ensureAevumNetwork(provider);
  assert.equal(r.added, true);
  assert.deepEqual(seen, ['wallet_switchEthereumChain', 'wallet_addEthereumChain', 'wallet_switchEthereumChain'].slice(0, 2));
});

test('WALLET 04: non 4902 errors propagate', async () => {
  const provider = {
    request: async () => { const e = new Error('user rejected'); e.code = 4001; throw e; }
  };
  await assert.rejects(() => W.ensureAevumNetwork(provider), /user rejected/);
});

test('WALLET 05: missing provider throws a clear error', () => {
  assert.throws(() => W.getProvider(null), /no EIP-1193/);
});
