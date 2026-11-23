#!/usr/bin/env node
/*
 * PQ PayGuard QDay Aevum preflight check.
 *
 * Validates everything the one command testnet deploy needs, without ever
 * printing secret material:
 *
 *   1. .env / environment    QDAY_PRIVATE_KEY present and well formed
 *   2. toolchain             forge (and optionally cast) on PATH
 *   3. network               live eth_chainId == 44005 (0xabe5),
 *                            eth_blockNumber advancing, tUSD8 decimals == 6
 *   4. deployer              derived address plus gas balance, so the faucet
 *                            step is verifiable before a deploy is attempted
 *
 * It then prints the exact deploy and explorer-verify commands to run.
 *
 * Usage:
 *   node scripts/qday-preflight.mjs            full check
 *   node scripts/qday-preflight.mjs --offline  skip all RPC probes
 *   node scripts/qday-preflight.mjs --json     machine readable report
 *
 * Exit code is 1 when any check fails, 0 otherwise. Safe to run offline and
 * safe to run repeatedly; it sends transactions and writes nothing.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import CH from '../src/chain.js';
import A from '../src/abi.js';
import { JsonRpc, privateKeyToAddress, isValidPrivateKey } from './lib/eth.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_TIMEOUT_MS = 8000;

// ---------------------------------------------------------------------------
// env parsing (values are never echoed back into any report)
// ---------------------------------------------------------------------------

export function parseEnvText(text) {
  const out = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    } else {
      const hash = val.indexOf(' #');
      if (hash !== -1) val = val.slice(0, hash).trim();
    }
    out[key] = val;
  }
  return out;
}

export function loadEnv(cwd, environ) {
  const envPath = join(cwd, '.env');
  const fileVars = existsSync(envPath) ? parseEnvText(readFileSync(envPath, 'utf8')) : {};
  // process environment wins over the file so exported overrides work.
  return { envPath, fileVars, merged: Object.assign({}, fileVars, environ || {}) };
}

// ---------------------------------------------------------------------------
// key validation: format + secp256k1 range. Returns metadata only.
// ---------------------------------------------------------------------------

export function checkDeployKey(rawValue) {
  if (rawValue === undefined || rawValue === null || String(rawValue).trim() === '') {
    return { present: false, ok: false, reason: 'QDAY_PRIVATE_KEY is not set' };
  }
  const hex = String(rawValue).trim().replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    return { present: true, ok: false, reason: 'key must be 64 hex characters (0x optional)' };
  }
  const priv = BigInt('0x' + hex);
  if (!isValidPrivateKey(priv)) {
    return { present: true, ok: false, reason: 'key is outside the secp256k1 range' };
  }
  return { present: true, ok: true, privKey: priv, deployer: privateKeyToAddress(priv) };
}

// ---------------------------------------------------------------------------
// toolchain probes
// ---------------------------------------------------------------------------

export function checkBinary(name, spawn) {
  const run = (spawn || spawnSync)(name, ['--version'], { encoding: 'utf8' });
  if (run.error || run.status !== 0) {
    return { ok: false, reason: name + ' not found on PATH' };
  }
  const first = String(run.stdout || '').split('\n')[0].trim();
  return { ok: true, version: first || name + ' present' };
}

// ---------------------------------------------------------------------------
// network probes. All failures degrade to a status line, never a crash.
// ---------------------------------------------------------------------------

function timedFetch(fetchImpl, timeoutMs) {
  const base = fetchImpl || fetch;
  return (url, init) => base(url, Object.assign({}, init, { signal: AbortSignal.timeout(timeoutMs) }));
}

export async function probeNetwork(rpcUrl, opts) {
  const o = opts || {};
  const rpc = new JsonRpc(rpcUrl, { fetch: timedFetch(o.fetchImpl, o.timeoutMs || DEFAULT_TIMEOUT_MS) });
  const out = { rpcUrl, reachable: false };
  try {
    out.chainId = await rpc.chainId();
    out.reachable = true;
  } catch (e) {
    out.error = 'chainId probe failed: ' + (e && e.message ? e.message : String(e));
    return out;
  }
  try {
    out.blockNumber = await rpc.blockNumber();
  } catch (e) {
    out.blockError = e && e.message ? e.message : String(e);
  }
  try {
    const raw = await rpc.ethCall(CH.TUSD8.address, A.encodeCall(CH.TOKEN_ABI.decimals, []));
    out.tusd8Decimals = Number(A.decodeArgs(['uint8'], raw)[0]);
  } catch (e) {
    out.tusd8Error = e && e.message ? e.message : String(e);
  }
  if (o.deployer) {
    try {
      out.deployerBalanceWei = (await rpc.balance(o.deployer)).toString();
    } catch (e) {
      out.balanceError = e && e.message ? e.message : String(e);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// command builders
// ---------------------------------------------------------------------------

export function constructorArgsHex(tokenAddress) {
  return '0x' + tokenAddress.slice(2).toLowerCase().padStart(64, '0');
}

export function buildVerifyCommand(tokenAddress, deployedAddress) {
  const addr = deployedAddress || '<DEPLOYED_ADDRESS>';
  return 'forge verify-contract ' + addr + ' \\\n' +
    '  contracts/PQPayGuardEscrow.sol:PQPayGuardEscrow \\\n' +
    '  --chain-id ' + CH.NETWORK.chainId + ' \\\n' +
    '  --verifier blockscout \\\n' +
    '  --verifier-url ' + CH.NETWORK.explorerUrl + '/api/ \\\n' +
    '  --constructor-args ' + constructorArgsHex(tokenAddress);
}

// ---------------------------------------------------------------------------
// preflight runner. Injectable env/spawn/fetch keep it fully testable.
// ---------------------------------------------------------------------------

export async function runPreflight(opts) {
  const o = opts || {};
  const cwd = o.cwd || ROOT;
  const checks = [];
  const push = (id, status, detail, fix) => {
    const c = { id, status, detail };
    if (fix) c.fix = fix;
    checks.push(c);
    return c;
  };

  // -- environment files ---------------------------------------------------
  const examplePath = join(cwd, '.env.example');
  if (!existsSync(examplePath)) {
    push('env-example', 'FAIL', '.env.example is missing');
  } else {
    push('env-example', 'PASS', '.env.example present (placeholders only)');
  }

  const { envPath, fileVars, merged } = loadEnv(cwd, o.env || process.env);
  const fileHasKey = Object.prototype.hasOwnProperty.call(fileVars, 'QDAY_PRIVATE_KEY') &&
    String(fileVars.QDAY_PRIVATE_KEY).trim() !== '';
  const envHasKey = (o.env || process.env).QDAY_PRIVATE_KEY !== undefined &&
    String((o.env || process.env).QDAY_PRIVATE_KEY).trim() !== '';
  if (existsSync(envPath)) {
    push('env-file', 'PASS', '.env present' + (fileHasKey ? ' with a key entry' : ''));
  } else if (envHasKey) {
    push('env-file', 'PASS', 'no .env, but QDAY_PRIVATE_KEY is exported in the environment');
  } else {
    push('env-file', 'FAIL', 'no .env file and no exported QDAY_PRIVATE_KEY',
      'run: cp .env.example .env, then paste a dedicated testnet-only key');
  }

  // -- deploy key ------------------------------------------------------------
  const key = checkDeployKey(merged.QDAY_PRIVATE_KEY);
  if (!key.ok) {
    push('key', 'FAIL', key.reason,
      'generate a dedicated testnet-only key; never reuse a real-funds key');
  } else {
    push('key', 'PASS', 'QDAY_PRIVATE_KEY valid, deployer ' + key.deployer + ' (key never printed)');
  }

  // -- toolchain ---------------------------------------------------------------
  const forge = checkBinary('forge', o.spawn);
  if (forge.ok) push('forge', 'PASS', forge.version);
  else push('forge', 'FAIL', forge.reason, 'install Foundry: https://getfoundry.sh');
  const cast = checkBinary('cast', o.spawn);
  if (cast.ok) push('cast', 'PASS', cast.version);
  else push('cast', 'WARN', cast.reason + ' (only needed for manual ABI lookups)');

  // -- network -------------------------------------------------------------------
  const rpcUrl = merged.QDAY_RPC_URL || CH.NETWORK.rpcUrl;
  if (o.offline) {
    push('rpc-chain', 'SKIP', 'offline mode, no RPC probes were run');
    push('rpc-block', 'SKIP', 'offline mode');
    push('token', 'SKIP', 'offline mode');
    push('balance', 'SKIP', 'offline mode');
  } else {
    const net = await probeNetwork(rpcUrl, {
      fetchImpl: o.fetchImpl,
      timeoutMs: o.timeoutMs,
      deployer: key.ok ? key.deployer : null
    });
    if (!net.reachable) {
      push('rpc-chain', 'FAIL', net.error + ' at ' + rpcUrl,
        'check connectivity, or rerun with --offline to skip');
      push('rpc-block', 'SKIP', 'RPC unreachable');
      push('token', 'SKIP', 'RPC unreachable');
      push('balance', 'SKIP', 'RPC unreachable');
    } else {
      if (net.chainId === CH.NETWORK.chainId) {
        push('rpc-chain', 'PASS', 'eth_chainId ' + CH.NETWORK.chainIdHex +
          ' (' + CH.NETWORK.chainId + ') on ' + rpcUrl);
      } else {
        push('rpc-chain', 'FAIL', 'expected chain ' + CH.NETWORK.chainId +
          ' (' + CH.NETWORK.chainIdHex + '), RPC returned ' + net.chainId,
          'point QDAY_RPC_URL at ' + CH.NETWORK.rpcUrl);
      }
      if (typeof net.blockNumber === 'number' && net.blockNumber > 0) {
        push('rpc-block', 'PASS', 'eth_blockNumber ' + net.blockNumber);
      } else {
        push('rpc-block', 'FAIL', net.blockError || 'no block number returned');
      }
      if (net.tusd8Decimals === CH.TUSD8.decimals) {
        push('token', 'PASS', 'tUSD8 ' + CH.TUSD8.address + ' decimals() == ' + CH.TUSD8.decimals);
      } else {
        push('token', 'WARN', net.tusd8Error ||
          ('tUSD8 decimals() read ' + net.tusd8Decimals + ', expected ' + CH.TUSD8.decimals));
      }
      if (!key.ok) {
        push('balance', 'SKIP', 'no valid deployer key');
      } else if (net.deployerBalanceWei !== undefined && BigInt(net.deployerBalanceWei) > 0n) {
        push('balance', 'PASS', 'deployer ' + key.deployer + ' holds ' +
          CH.formatTokenUnits(BigInt(net.deployerBalanceWei), 18) + ' tQDAY gas');
      } else {
        push('balance', 'WARN', 'deployer ' + key.deployer + ' has zero gas',
          'fund it from ' + CH.NETWORK.faucetUrl);
      }
    }
  }

  const failed = checks.filter((c) => c.status === 'FAIL').length;
  const tokenAddr = (merged.QDAY_TUSD8 || CH.TUSD8.address);
  return {
    ok: failed === 0,
    checks,
    commands: {
      deploy: 'node scripts/deploy-qday.mjs',
      verify: buildVerifyCommand(tokenAddr),
      faucet: CH.NETWORK.faucetUrl
    },
    deployer: key.ok ? key.deployer : null,
    rpcUrl
  };
}

export function formatReport(result) {
  const lines = [];
  lines.push('PQ PayGuard preflight - QDay Aevum testnet (chain ' +
    CH.NETWORK.chainId + ' / ' + CH.NETWORK.chainIdHex + ')');
  for (const c of result.checks) {
    lines.push('  ' + c.status.padEnd(4) + ' ' + c.id.padEnd(11) + ' ' + c.detail);
    if (c.fix) lines.push('       -> ' + c.fix);
  }
  lines.push('');
  if (result.ok) {
    lines.push('Ready for 1-command deploy with the funded testnet key:');
  } else {
    lines.push('Fix the FAIL lines above, then run the deploy:');
  }
  lines.push('  ' + result.commands.deploy);
  lines.push('');
  lines.push('Then verify the contract source on the Blockscout explorer:');
  for (const l of result.commands.verify.split('\n')) lines.push('  ' + l);
  lines.push('');
  lines.push('Gas for the deployer comes from the official faucet only: ' + result.commands.faucet);
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log('usage: node scripts/qday-preflight.mjs [--offline] [--json]');
    return;
  }
  const result = await runPreflight({
    offline: args.includes('--offline')
  });
  if (args.includes('--json')) {
    const { checks, ok, commands, deployer, rpcUrl } = result;
    console.log(JSON.stringify({ ok, checks, commands, deployer, rpcUrl }, null, 2));
  } else {
    console.log(formatReport(result));
  }
  process.exit(result.ok ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => {
    console.error('preflight error: ' + (e && e.message ? e.message : String(e)));
    process.exit(1);
  });
}
