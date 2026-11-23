'use strict';

/*
 * Tests for scripts/qday-preflight.mjs. All network and process access is
 * stubbed: the fetch stub answers canned JSON-RPC payloads and the spawn stub
 * answers canned version strings, so the suite runs fully offline and
 * deterministically. A key property under test is that report output never
 * contains the raw private key, only the derived public deployer address.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

let pf;
test.before(async () => {
  pf = await import('../scripts/qday-preflight.mjs');
});

// anvil-style dev key 0x...01 derives this well known address; it is a public
// constant of the secp256k1 curve, not a secret
const DEV_KEY = '0x' + '0'.repeat(63) + '1';
const DEV_KEY_HEX = DEV_KEY.slice(2);
const DEV_ADDR = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';
const TUSD8 = '0x456569838f1d43009A91ebA4263147Afd7233483';

function tmpRepo(t, files) {
  const dir = mkdtempSync(join(tmpdir(), 'pqpg-pref-'));
  for (const [name, content] of Object.entries(files || {})) {
    writeFileSync(join(dir, name), content);
  }
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function spawnOk() {
  return (name) => ({ status: 0, stdout: name + ' Version: 1.10.0-test\n' });
}
function spawnMissing() {
  return () => ({ status: null, error: new Error('spawn ENOENT') });
}

function fakeFetch(handlers) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    const fn = handlers[body.method];
    if (!fn) throw new Error('no stub for ' + body.method);
    const result = await fn(body.params || []);
    if (result instanceof Error) throw result;
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: body.id, result }) };
  };
}

const U8_6 = '0x' + '0'.repeat(63) + '6';
const GOOD_NET = {
  'eth_chainId': async () => '0xabe5',
  'eth_blockNumber': async () => '0x3c144b',
  'eth_call': async () => U8_6,
  'eth_getBalance': async () => '0xde0b6b3a7640000'
};

test('PREF 01: parseEnvText handles comments, quotes and junk lines', () => {
  const env = pf.parseEnvText([
    '# comment',
    'QDAY_PRIVATE_KEY=0x' + 'ab'.repeat(32),
    'QDAY_RPC_URL="https://example.invalid/rpc"',
    "QDAY_TUSD8='0x1234'",
    'SPACED = value # trailing comment',
    'not a line',
    '1BAD=skip',
    ''
  ].join('\n'));
  assert.equal(env.QDAY_PRIVATE_KEY, '0x' + 'ab'.repeat(32));
  assert.equal(env.QDAY_RPC_URL, 'https://example.invalid/rpc');
  assert.equal(env.QDAY_TUSD8, '0x1234');
  assert.equal(env.SPACED, 'value');
  assert.equal(env['not a line'], undefined);
  assert.equal(env['1BAD'], undefined);
});

test('PREF 02: checkDeployKey validates format and secp256k1 range', () => {
  assert.equal(pf.checkDeployKey(undefined).ok, false);
  assert.equal(pf.checkDeployKey('').ok, false);
  assert.equal(pf.checkDeployKey('   ').ok, false);
  assert.equal(pf.checkDeployKey('0x1234').ok, false);
  assert.equal(pf.checkDeployKey('zz' + '0'.repeat(62)).ok, false);
  assert.equal(pf.checkDeployKey('0x' + '0'.repeat(64)).ok, false); // zero key
  const good = pf.checkDeployKey(DEV_KEY);
  assert.equal(good.ok, true);
  assert.equal(good.deployer, DEV_ADDR);
  assert.equal(pf.checkDeployKey(DEV_KEY_HEX).ok, true); // no 0x prefix
});

test('PREF 03: verify command is fully formed for the Blockscout explorer', () => {
  const args = pf.constructorArgsHex(TUSD8);
  assert.equal(args.length, 66);
  assert.equal(args, '0x' + '0'.repeat(24) + TUSD8.slice(2).toLowerCase());
  const cmd = pf.buildVerifyCommand(TUSD8);
  assert.match(cmd, /forge verify-contract <DEPLOYED_ADDRESS>/);
  assert.match(cmd, /contracts\/PQPayGuardEscrow\.sol:PQPayGuardEscrow/);
  assert.match(cmd, /--chain-id 44005/);
  assert.match(cmd, /--verifier blockscout/);
  assert.match(cmd, /--verifier-url https:\/\/explorer-test\.qday\.info\/api\//);
  assert.match(cmd, new RegExp('--constructor-args ' + args));
  const withAddr = pf.buildVerifyCommand(TUSD8, '0x' + 'ab'.repeat(20));
  assert.match(withAddr, /forge verify-contract 0xabab/);
});

test('PREF 04: offline mode skips every RPC probe', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'QDAY_PRIVATE_KEY=paste-here\n' });
  const r = await pf.runPreflight({
    cwd: dir, env: { QDAY_PRIVATE_KEY: DEV_KEY }, spawn: spawnOk(), offline: true
  });
  const skipped = r.checks.filter((c) => c.status === 'SKIP').map((c) => c.id);
  assert.deepEqual(skipped, ['rpc-chain', 'rpc-block', 'token', 'balance']);
  assert.equal(r.ok, true);
  assert.equal(r.deployer, DEV_ADDR);
});

test('PREF 05: missing key and missing .env produce FAIL plus a fix hint', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'QDAY_PRIVATE_KEY=paste-here\n' });
  const r = await pf.runPreflight({ cwd: dir, env: {}, spawn: spawnOk(), offline: true });
  assert.equal(r.ok, false);
  const key = r.checks.find((c) => c.id === 'key');
  const envf = r.checks.find((c) => c.id === 'env-file');
  assert.equal(key.status, 'FAIL');
  assert.equal(envf.status, 'FAIL');
  assert.match(envf.fix, /cp \.env\.example \.env/);
  assert.match(key.fix, /testnet-only/);
});

test('PREF 06: full live-shaped probe passes against a stub RPC', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const r = await pf.runPreflight({
    cwd: dir,
    env: { QDAY_PRIVATE_KEY: DEV_KEY, QDAY_RPC_URL: 'http://127.0.0.1:9/rpc' },
    spawn: spawnOk(),
    fetchImpl: fakeFetch(GOOD_NET)
  });
  assert.equal(r.ok, true);
  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  assert.equal(byId['rpc-chain'].status, 'PASS');
  assert.match(byId['rpc-chain'].detail, /0xabe5/);
  assert.match(byId['rpc-block'].detail, /3937355/); // 0x3c144b
  assert.equal(byId.token.status, 'PASS');
  assert.equal(byId.balance.status, 'PASS');
  assert.match(byId.balance.detail, /1 tQDAY/);
});

test('PREF 07: wrong chain id fails loudly', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const r = await pf.runPreflight({
    cwd: dir,
    env: { QDAY_PRIVATE_KEY: DEV_KEY },
    spawn: spawnOk(),
    fetchImpl: fakeFetch(Object.assign({}, GOOD_NET, { 'eth_chainId': async () => '0x1' }))
  });
  assert.equal(r.ok, false);
  const c = r.checks.find((x) => x.id === 'rpc-chain');
  assert.equal(c.status, 'FAIL');
  assert.match(c.detail, /expected chain 44005/);
});

test('PREF 08: unreachable RPC degrades to FAIL plus skips, no crash', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const r = await pf.runPreflight({
    cwd: dir,
    env: { QDAY_PRIVATE_KEY: DEV_KEY },
    spawn: spawnOk(),
    fetchImpl: async () => { throw new Error('ENOTFOUND'); }
  });
  assert.equal(r.ok, false);
  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  assert.equal(byId['rpc-chain'].status, 'FAIL');
  assert.match(byId['rpc-chain'].detail, /ENOTFOUND/);
  assert.equal(byId['rpc-block'].status, 'SKIP');
  assert.equal(byId.balance.status, 'SKIP');
});

test('PREF 09: zero gas balance is a WARN pointing at the faucet', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const r = await pf.runPreflight({
    cwd: dir,
    env: { QDAY_PRIVATE_KEY: DEV_KEY },
    spawn: spawnOk(),
    fetchImpl: fakeFetch(Object.assign({}, GOOD_NET, { 'eth_getBalance': async () => '0x0' }))
  });
  const bal = r.checks.find((c) => c.id === 'balance');
  assert.equal(bal.status, 'WARN');
  assert.match(bal.fix, /faucet\.qday\.info/);
  assert.equal(r.ok, true); // warnings do not fail the run
});

test('PREF 10: a tUSD8 decimals mismatch is a WARN, not a crash', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const r = await pf.runPreflight({
    cwd: dir,
    env: { QDAY_PRIVATE_KEY: DEV_KEY },
    spawn: spawnOk(),
    fetchImpl: fakeFetch(Object.assign({}, GOOD_NET, { 'eth_call': async () => '0x' + '0'.repeat(63) + '8' }))
  });
  const tok = r.checks.find((c) => c.id === 'token');
  assert.equal(tok.status, 'WARN');
  assert.match(tok.detail, /read 8, expected 6/);
});

test('PREF 11: missing forge fails the run; missing cast only warns', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const noForge = await pf.runPreflight({
    cwd: dir, env: { QDAY_PRIVATE_KEY: DEV_KEY }, spawn: spawnMissing(), offline: true
  });
  assert.equal(noForge.ok, false);
  assert.equal(noForge.checks.find((c) => c.id === 'forge').status, 'FAIL');
  const noCast = await pf.runPreflight({
    cwd: dir, env: { QDAY_PRIVATE_KEY: DEV_KEY },
    spawn: (n) => n === 'forge' ? { status: 0, stdout: 'forge 1.10.0\n' } : { error: new Error('ENOENT') },
    offline: true
  });
  assert.equal(noCast.ok, true);
  assert.equal(noCast.checks.find((c) => c.id === 'cast').status, 'WARN');
});

test('PREF 12: report never prints the key; it prints the deploy runbook', async (t) => {
  const dir = tmpRepo(t, { '.env.example': 'x\n' });
  const secret = '0x' + 'ab'.repeat(32); // deterministic fake key for this test only
  const r = await pf.runPreflight({
    cwd: dir, env: { QDAY_PRIVATE_KEY: secret }, spawn: spawnOk(), offline: true
  });
  const report = pf.formatReport(r);
  assert.ok(!report.includes(secret), 'report leaked the raw key');
  assert.ok(!report.includes(secret.slice(2)), 'report leaked the raw key hex');
  assert.ok(!JSON.stringify(r.checks).includes(secret.slice(2)), 'checks leaked key material');
  assert.match(report, /node scripts\/deploy-qday\.mjs/);
  assert.match(report, /forge verify-contract/);
  assert.match(report, /faucet\.qday\.info/);
  assert.match(report, /Ready for 1-command deploy/);
});

test('PREF 13: .env file supplies the key when the environment does not', async (t) => {
  const dir = tmpRepo(t, {
    '.env.example': 'QDAY_PRIVATE_KEY=paste-here\n',
    '.env': 'QDAY_PRIVATE_KEY=' + DEV_KEY + '\n'
  });
  const r = await pf.runPreflight({ cwd: dir, env: {}, spawn: spawnOk(), offline: true });
  assert.equal(r.ok, true);
  assert.equal(r.deployer, DEV_ADDR);
  assert.equal(r.checks.find((c) => c.id === 'env-file').status, 'PASS');
});
