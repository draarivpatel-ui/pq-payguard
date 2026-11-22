#!/usr/bin/env node
/*
 * Deploy PQPayGuardEscrow to the QDay Aevum testnet and run a read-only
 * verification of the deployment.
 *
 * Required environment:
 *   QDAY_PRIVATE_KEY   hex private key of a dedicated TESTNET-ONLY account
 *                      (with or without the 0x prefix). Never commit it.
 *
 * Optional environment:
 *   QDAY_RPC_URL       override RPC endpoint (default: official testnet)
 *   QDAY_TUSD8         override token address (default: official tUSD8)
 *
 * Usage:
 *   QDAY_PRIVATE_KEY=... node scripts/deploy-qday.mjs
 *
 * The script is idempotent-safe in the sense that it deploys a fresh
 * contract per run; it never reuses or mutates an existing deployment.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import CH from '../src/chain.js';
import A from '../src/abi.js';
import {
  JsonRpc, privateKeyToAddress, isValidPrivateKey,
  deployContract
} from './lib/eth.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function fail(msg) {
  console.error('error: ' + msg);
  process.exit(1);
}

// ---- key handling -----------------------------------------------------------
const rawKey = process.env.QDAY_PRIVATE_KEY;
if (!rawKey) {
  fail(
    'QDAY_PRIVATE_KEY is not set.\n' +
    '  Export a dedicated testnet-only key first:\n' +
    '    export QDAY_PRIVATE_KEY=<hex key>\n' +
    '  Never reuse a key that has ever held real funds.'
  );
}
const keyHex = rawKey.trim().replace(/^0x/, '');
if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
  fail('QDAY_PRIVATE_KEY must be 64 hex characters (0x prefix optional).');
}
const privKey = BigInt('0x' + keyHex);
if (!isValidPrivateKey(privKey)) fail('QDAY_PRIVATE_KEY is outside the secp256k1 key range.');
const deployer = privateKeyToAddress(privKey);
console.log('deployer: ' + deployer + '  (derived, key never printed)');

// ---- network ----------------------------------------------------------------
const rpcUrl = process.env.QDAY_RPC_URL || CH.NETWORK.rpcUrl;
const rpc = new JsonRpc(rpcUrl);
const chainId = await rpc.chainId().catch((e) => fail('RPC unreachable at ' + rpcUrl + ': ' + e.message));
if (chainId !== CH.NETWORK.chainId) {
  fail('chain id mismatch: expected ' + CH.NETWORK.chainId + ', got ' + chainId);
}
console.log('chain: ' + CH.NETWORK.name + ' (id ' + chainId + ') via ' + rpcUrl);

const balance = await rpc.balance(deployer);
if (balance === 0n) {
  fail(
    'deployer has zero gas balance.\n' +
    '  Fund it from the official faucet first: ' + CH.NETWORK.faucetUrl +
    '\n  Address: ' + deployer
  );
}
console.log('gas balance: ' + balance + ' wei');

// ---- compile ----------------------------------------------------------------
const build = spawnSync('forge', ['build'], { cwd: ROOT, stdio: 'inherit' });
if (build.status !== 0) fail('forge build failed; run node scripts/compile.mjs for details');
const artifactPath = join(ROOT, 'out', 'PQPayGuardEscrow.sol', 'PQPayGuardEscrow.json');
if (!existsSync(artifactPath)) fail('missing artifact ' + artifactPath);
const meta = JSON.parse(readFileSync(artifactPath, 'utf8'));
const bytecode = '0x' + meta.bytecode.object;

// ---- deploy -----------------------------------------------------------------
const tokenAddress = (process.env.QDAY_TUSD8 || CH.TUSD8.address).toLowerCase();
if (!CH.isValidAddress(tokenAddress)) fail('bad token address: ' + tokenAddress);
console.log('token: ' + tokenAddress + ' (' + CH.TUSD8.symbol + ', ' + CH.TUSD8.decimals + ' decimals)');

console.log('deploying PQPayGuardEscrow ...');
const dep = await deployContract(rpc, privKey, BigInt(CH.NETWORK.chainId), bytecode, ['address'], [tokenAddress]);
console.log('deployed: ' + dep.address);
console.log('  tx: ' + dep.txHash);
console.log('  explorer: ' + CH.explorerTxUrl(dep.txHash));

// ---- verify -----------------------------------------------------------------
const tokenOnChain = await rpc.ethCall(dep.address, A.encodeCall(CH.ESCROW_ABI.token, []));
const decoded = A.decodeArgs(['address'], tokenOnChain)[0];
if (decoded.toLowerCase() !== tokenAddress) {
  fail('post-deploy check failed: token() returned ' + decoded);
}
const nextEscrow = await rpc.ethCall(dep.address, A.encodeCall(CH.ESCROW_ABI.nextEscrowId, []));
const nextSession = await rpc.ethCall(dep.address, A.encodeCall(CH.ESCROW_ABI.nextSessionId, []));

const summary = {
  network: CH.NETWORK.name,
  chainId: CH.NETWORK.chainId,
  rpcUrl,
  contract: 'PQPayGuardEscrow',
  address: dep.address,
  deployer,
  token: tokenAddress,
  deployTx: dep.txHash,
  explorerTx: CH.explorerTxUrl(dep.txHash),
  explorerAddress: CH.explorerAddressUrl(dep.address),
  verified: {
    tokenViewMatches: true,
    nextEscrowId: Number(A.decodeArgs(['uint256'], nextEscrow)[0]),
    nextSessionId: Number(A.decodeArgs(['uint256'], nextSession)[0])
  },
  deployedAt: new Date().toISOString()
};

const outDir = join(ROOT, 'deployments');
mkdirSync(outDir, { recursive: true });
const outFile = join(outDir, 'qday-testnet.json');
writeFileSync(outFile, JSON.stringify(summary, null, 2) + '\n');
console.log('verification passed; summary written to ' + outFile);
console.log('next: approve tUSD8 spend + create a session through the demo UI or scripts');
