'use strict';

/*
 * Anvil parity test: compiles the real contracts with forge and drives the
 * deployed PQPayGuardEscrow over live JSON-RPC against a local anvil EVM.
 * Every transaction is a real signed EIP-155 call through scripts/lib/eth.mjs,
 * so this exercises the full compile + deploy + encode + sign + execute +
 * decode loop, and checks the JS commitment byte-for-byte against the
 * contract's own computeCommitment precompile output.
 *
 * Skipped automatically when forge/anvil binaries are unavailable.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

const CH = require('../src/chain.js');
const A = require('../src/abi.js');
const R = require('../src/risk.js');
const C = require('../src/commit.js');

const ROOT = join(__dirname, '..');
const FORGE = process.env.PQPG_FORGE_BIN || 'forge';
const ANVIL = process.env.PQPG_ANVIL_BIN || 'anvil';
const PORT = 8545;
const RPC_URL = 'http://127.0.0.1:' + PORT;
const CHAIN_ID = 44005n;

function which(bin) {
  const r = spawnSync('sh', ['-lc', 'command -v ' + JSON.stringify(bin)]);
  if (r.status !== 0) return null;
  const p = String(r.stdout).trim().split('\n')[0];
  return p || null;
}

test('anvil parity: full escrow lifecycle on a real EVM', { timeout: 240000, concurrency: false }, async (t) => {
  const forgePath = which(FORGE);
  const anvilPath = which(ANVIL);
  if (!forgePath || !anvilPath) {
    t.skip('forge/anvil not installed');
    return;
  }

  // 1. compile with the same settings foundry.toml declares
  const build = spawnSync(forgePath, ['build'], { cwd: ROOT });
  assert.equal(build.status, 0, 'forge build failed:\n' + String(build.stderr).slice(-2000));

  const outDir = join(ROOT, 'out');
  const escrowMeta = JSON.parse(readFileSync(
    join(outDir, 'PQPayGuardEscrow.sol', 'PQPayGuardEscrow.json'), 'utf8'));
  const tokenMeta = JSON.parse(readFileSync(
    join(outDir, 'MockTUSD8.sol', 'MockTUSD8.json'), 'utf8'));
  const escrowBytecode = '0x' + escrowMeta.bytecode.object;
  const tokenBytecode = '0x' + tokenMeta.bytecode.object;

  // 2. spawn anvil on the Aevum chain id and harvest its dev keys
  const anvil = spawn(anvilPath,
    ['--port', String(PORT), '--chain-id', String(CHAIN_ID), '--accounts', '12', '--balance', '10000'],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { try { anvil.kill('SIGKILL'); } catch {} });

  const keyMap = new Map();
  let anvilBuf = '';
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('anvil startup timeout\n' + anvilBuf.slice(-2000))), 20000);
    anvil.stdout.on('data', (d) => {
      anvilBuf += String(d);
      const m = anvilBuf.match(/Private Keys[\s\S]*$/);
      if (m) {
        for (const km of m[0].matchAll(/\((\d+)\)\s+0x([0-9a-f]{64})/g)) {
          keyMap.set(Number(km[1]), '0x' + km[2]);
        }
      }
      if (/Listening on/.test(anvilBuf)) { clearTimeout(to); resolve(); }
    });
    anvil.stderr.on('data', (d) => { anvilBuf += String(d); });
    anvil.on('exit', (c) => reject(new Error('anvil exited ' + c + '\n' + anvilBuf.slice(-500))));
  });
  assert.ok(keyMap.size >= 12, 'expected 12 anvil keys, got ' + keyMap.size);

  const eth = await import('../scripts/lib/eth.mjs');
  const RPC = require('../src/rpc.js');
  const rpc = new eth.JsonRpc(RPC_URL);

  const priv = (i) => BigInt(keyMap.get(i));
  const addr = (i) => eth.privateKeyToAddress(priv(i));
  const PAYER = addr(0);
  const OPERATOR = addr(1);
  const GUARDIAN = addr(2);
  const RECIP = addr(3);
  const MERCH2 = addr(4);
  const STRANGER = addr(5);

  assert.equal(await rpc.chainId(), 44005, 'anvil not on chain 44005');

  // 3. deploy token + escrow
  const tok = await eth.deployContract(rpc, priv(0), CHAIN_ID, tokenBytecode, [], []);
  const token = tok.address.toLowerCase();
  const esc = await eth.deployContract(rpc, priv(0), CHAIN_ID, escrowBytecode, ['address'], [token]);
  const escrow = esc.address.toLowerCase();

  const call = (data) => rpc.ethCall(escrow, data);
  const tokenBalance = async (who) =>
    A.decodeArgs(['uint256'], await rpc.ethCall(token, A.encodeCall('balanceOf(address)', [who])))[0];

  assert.equal(
    await call(A.encodeCall(CH.ESCROW_ABI.token, [])),
    '0x' + '0'.repeat(24) + token.slice(2));
  assert.equal(
    A.decodeArgs(['string'], await rpc.ethCall(token, A.encodeCall('symbol()', [])))[0],
    'tUSD8');
  assert.equal(
    A.decodeArgs(['uint8'], await rpc.ethCall(token, A.encodeCall('decimals()', [])))[0],
    6n);

  // 4. fund payer, approve escrow
  await eth.sendCall(rpc, priv(0), CHAIN_ID, token, 'mint(address,uint256)', [PAYER, 50_000_000n]);
  await eth.sendCall(rpc, priv(0), CHAIN_ID, token, 'approve(address,uint256)', [escrow, 50_000_000n]);
  assert.equal(await tokenBalance(PAYER), 50_000_000n);

  // 5. create session; sessionId is the first indexed topic of SessionUpdated
  const now = Math.floor(Date.now() / 1000);
  const sess = await eth.sendCall(rpc, priv(0), CHAIN_ID, escrow, CH.ESCROW_ABI.createSession, [
    OPERATOR, GUARDIAN, 25_000_000n, 100_000_000n,
    BigInt(now + 3600), 0n, 0n
  ]);
  const sessionId = BigInt(sess.receipt.logs[0].topics[1]);

  const sessView = await RPC.readSession(escrow, sessionId, { rpcUrl: RPC_URL });
  assert.equal(sessView.payer.toLowerCase(), PAYER);
  assert.equal(sessView.operator.toLowerCase(), OPERATOR);
  assert.equal(sessView.guardian.toLowerCase(), GUARDIAN);
  assert.equal(sessView.maxPerTx, 25_000_000n);
  assert.equal(sessView.capTotal, 100_000_000n);
  assert.equal(sessView.paused, false);
  assert.equal(sessView.revoked, false);

  // helper: full risk -> attestation -> commitment -> createEscrow pipeline
  let nonce = 0;
  async function fundEscrow(recipient, amountRaw, riskInput, deadline) {
    const r = R.exposureScore(riskInput);
    const att = await C.buildAttestation({
      payer: PAYER, recipient, amountRaw, score: r.score,
      tier: r.tierName, scheme: riskInput.scheme, factors: r.factors,
      sessionId: Number(sessionId), nonce: String(nonce++), issuedAt: now
    });
    const commitment = C.computeCommitment({
      chainId: 44005, contractAddress: escrow, sessionId: Number(sessionId),
      payer: PAYER, recipient, amountRaw, riskScore: r.score,
      attestationHash: att.attestationHash, deadline
    });
    // parity: the contract's own precompile must reproduce the JS hash
    const onchain = await call(A.encodeCall(CH.ESCROW_ABI.computeCommitment, [
      sessionId, PAYER, recipient, amountRaw, BigInt(r.score), att.attestationHash, BigInt(deadline)
    ]));
    assert.equal(onchain.toLowerCase(), commitment, 'commitment parity failed');
    const res = await eth.sendCall(rpc, priv(1), CHAIN_ID, escrow, CH.ESCROW_ABI.createEscrow, [
      sessionId, recipient, amountRaw, BigInt(r.score),
      att.attestationHash, commitment, BigInt(deadline)
    ]);
    return { escrowId: BigInt(res.receipt.logs[0].topics[1]), score: r.score };
  }

  // 6. LOW: releases immediately to the recipient
  const low = await fundEscrow(RECIP, 5_000_000n, { scheme: 'falcon-512', valueTusd: 5, ageDays: 10 }, now + 600);
  assert.equal(low.score <= 29, true, 'expected low tier, got ' + low.score);
  await eth.sendCall(rpc, priv(5), CHAIN_ID, escrow, CH.ESCROW_ABI.release, [low.escrowId]);
  assert.equal(await tokenBalance(RECIP), 5_000_000n);

  // 7. HIGH: release blocked until the guardian co-signs
  const high = await fundEscrow(MERCH2, 7_000_000n,
    { scheme: 'rsa-2048', valueTusd: 5000, ageDays: 700 }, now + 600);
  assert.equal(high.score >= 60 && high.score <= 84, true, 'expected high tier, got ' + high.score);
  await assert.rejects(
    eth.sendCall(rpc, priv(5), CHAIN_ID, escrow, CH.ESCROW_ABI.release, [high.escrowId]),
    /reverted|estimation failed/);
  await assert.rejects(
    eth.sendCall(rpc, priv(5), CHAIN_ID, escrow, CH.ESCROW_ABI.guardianApprove, [high.escrowId]),
    /reverted|estimation failed/, 'non guardian approval must revert');
  await eth.sendCall(rpc, priv(2), CHAIN_ID, escrow, CH.ESCROW_ABI.guardianApprove, [high.escrowId]);
  await eth.sendCall(rpc, priv(5), CHAIN_ID, escrow, CH.ESCROW_ABI.release, [high.escrowId]);
  assert.equal(await tokenBalance(MERCH2), 7_000_000n);

  // 8. CRITICAL: quarantined; release reverts; payer reclaims via revokeEscrow
  const crit = await fundEscrow(STRANGER, 9_000_000n,
    { scheme: 'rsa-2048', valueTusd: 50000, ageDays: 3000, deprecated: true, keyRevealed: true },
    now + 600);
  assert.equal(crit.score >= 85, true, 'expected critical tier, got ' + crit.score);
  await assert.rejects(
    eth.sendCall(rpc, priv(5), CHAIN_ID, escrow, CH.ESCROW_ABI.release, [crit.escrowId]),
    /reverted|estimation failed/);
  const payerBefore = await tokenBalance(PAYER);
  await eth.sendCall(rpc, priv(0), CHAIN_ID, escrow, CH.ESCROW_ABI.revokeEscrow, [crit.escrowId]);
  assert.equal(await tokenBalance(PAYER), payerBefore + 9_000_000n, 'payer did not reclaim');
  assert.equal(await tokenBalance(STRANGER), 0n, 'quarantined funds must never reach the recipient');

  // 9. tampered commitment is rejected by the gate itself
  await assert.rejects(
    eth.sendCall(rpc, priv(1), CHAIN_ID, escrow, CH.ESCROW_ABI.createEscrow, [
      sessionId, STRANGER, 1_000_000n, 10n,
      '0x' + 'cd'.repeat(32), '0x' + 'ab'.repeat(32), BigInt(now + 600)
    ]),
    /reverted|estimation failed/, 'mismatched commitment must revert');

  // 10. view parity: sim status names vs the chain's enum ordinals
  const esc0 = await RPC.readEscrow(escrow, low.escrowId, { rpcUrl: RPC_URL });
  assert.equal(CH.STATUS_NAMES[esc0.status], 'released');
  const escCrit = await RPC.readEscrow(escrow, crit.escrowId, { rpcUrl: RPC_URL });
  assert.equal(CH.STATUS_NAMES[escCrit.status], 'revoked');
  assert.equal(CH.TIER_NAMES[escCrit.tier], 'critical');

  // 11. releaseBlocker view round trips through the same encoder the UI uses
  const blocker = await RPC.readReleaseBlocker(escrow, high.escrowId, { rpcUrl: RPC_URL });
  assert.equal(blocker, 'not_funded'); // already released

  // 12. session spent accounting reflects the funded escrows
  const sessEnd = await RPC.readSession(escrow, sessionId, { rpcUrl: RPC_URL });
  assert.equal(sessEnd.spent, 5_000_000n + 7_000_000n + 9_000_000n);
});
