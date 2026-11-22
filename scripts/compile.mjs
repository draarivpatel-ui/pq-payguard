#!/usr/bin/env node
/*
 * Compile the contracts with forge and print artifact facts.
 *
 * Usage:
 *   node scripts/compile.mjs
 *
 * Requires forge on PATH (Foundry). Writes forge output under out/.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { keccak256, hexToBytes, bytesToHex } from '../src/keccak.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const forge = spawnSync('forge', ['build'], { cwd: ROOT, stdio: 'inherit' });
if (forge.status !== 0) {
  console.error('forge build failed (status ' + forge.status + '). Is Foundry installed?');
  process.exit(forge.status ?? 1);
}

for (const name of ['PQPayGuardEscrow', 'MockTUSD8']) {
  const dir = join(ROOT, 'out', name + '.sol', name + '.json');
  if (!existsSync(dir)) {
    console.error('missing artifact: ' + dir);
    process.exit(1);
  }
  const meta = JSON.parse(readFileSync(dir, 'utf8'));
  const bytecode = '0x' + meta.bytecode.object;
  const bytes = hexToBytes(bytecode);
  const hash = bytesToHex(keccak256(bytes));
  console.log(
    name.padEnd(18) +
    ' bytecode ' + String(bytes.length).padStart(5) + ' B' +
    '  keccak 0x' + hash
  );
}
console.log('artifacts written to out/');
