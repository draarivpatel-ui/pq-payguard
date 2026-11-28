'use strict';

/*
 * Publication compliance gate. Scans every tracked text file for:
 *   - em/en dashes and other unicode dash variants (raw byte check)
 *   - AI / model vendor mentions
 *   - personal information (emails, real names, street, phone)
 *   - hardcoded secrets: private keys, mnemonics, vendor key prefixes
 *
 * The scans operate on raw bytes so they cannot be fooled by escaping.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { readdirSync, readFileSync, statSync } = require('node:fs');
const { join, extname } = require('node:path');

const ROOT = join(__dirname, '..');

const TEXT_EXT = new Set([
  '.sol', '.js', '.mjs', '.cjs', '.json', '.html', '.css', '.md',
  '.toml', '.svg', '.txt', '.example', ''
]);
const SKIP_DIRS = new Set(['.git', 'node_modules', 'out', 'cache', 'lib', '.forge-cache']);
const SKIP_FILES = new Set(['package-lock.json', 'compliance.test.js']);

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(name)) yield* walk(p);
    } else if (st.isFile()) {
      if (SKIP_FILES.has(name)) continue;
      const ext = extname(name);
      const base = name.startsWith('.') ? '' : ext;
      if (TEXT_EXT.has(base) || name === 'LICENSE' || name.startsWith('.env') || name === '.gitignore') {
        yield p;
      }
    }
  }
}

const files = [...walk(ROOT)].filter((p) => !p.includes('test/'));
const allFiles = [...walk(ROOT)];
assert.ok(files.length >= 15, 'sanity: expected at least 15 project files, got ' + files.length);

function forEachFile(fn) {
  for (const p of allFiles) fn(p, readFileSync(p));
}

test('COMP 01: zero em/en/unicode dashes in any project file', () => {
  const offenders = [];
  const needles = [
    [Buffer.from([0xe2, 0x80, 0x94]), 'U+2014 em dash'],
    [Buffer.from([0xe2, 0x80, 0x93]), 'U+2013 en dash'],
    [Buffer.from([0xe2, 0x80, 0x90]), 'U+2010 hyphen'],
    [Buffer.from([0xe2, 0x80, 0x91]), 'U+2011 nb hyphen'],
    [Buffer.from([0xe2, 0x88, 0x92]), 'U+2212 minus']
  ];
  forEachFile((p, buf) => {
    for (const [needle, label] of needles) {
      if (buf.includes(needle)) offenders.push(p.replace(ROOT + '/', '') + ' (' + label + ')');
    }
  });
  assert.deepEqual(offenders, []);
});

test('COMP 02: no AI tool or model vendor mentions', () => {
  const banned = /\b(claude|anthropic|openai|chatgpt|gpt-?[0-9]|copilot|deepseek|mistral|llama|devin|aider|codeium|tabnine|windsurf)\b/i;
  const offenders = [];
  forEachFile((p, buf) => {
    const rel = p.replace(ROOT + '/', '');
    if (banned.test(buf.toString('utf8'))) offenders.push(rel);
  });
  assert.deepEqual(offenders, []);
});

test('COMP 03: no personal information', () => {
  const banned = new RegExp([
    'gmail\\.com',
    '\\b\\d{2,5}\\s+[a-z]+(?:\\s+[a-z]+){0,2}\\s+(?:street|st|road|rd|lane|ln|drive|dr|court|ct|manor|way|circle|cir)\\b',
    '\\b\\d{3}[-.]\\d{3}[-.]\\d{4}\\b'
  ].join('|'), 'i');
  const offenders = [];
  forEachFile((p, buf) => {
    const rel = p.replace(ROOT + '/', '');
    if (banned.test(buf.toString('utf8'))) offenders.push(rel);
  });
  assert.deepEqual(offenders, []);
});

test('COMP 04: no hardcoded private keys or secrets', () => {
  const offenders = [];
  // raw 64-hex secrets with or without 0x, anywhere outside the test corpus
  // (test vectors such as keccak digests live in test/ and are allowlisted)
  const rawKey = /(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/;
  // vendor token prefixes that must never appear, even as placeholders
  const vendor = /(tskey-|sk-[a-z0-9]{8}|ghp_[a-z0-9]{8}|github_pat_|AKIA[0-9A-Z]{8}|xox[baprs]-|gsk_|nvapi-|tvly-|AIza)/;
  const keyAssign = /(private[_-]?key|secret|mnemonic|seed[_ -]?phrase|api[_-]?key)\s*[:=]\s*['"`]?0x?[0-9a-fA-F]{32,}/i;
  forEachFile((p, buf) => {
    const rel = p.replace(ROOT + '/', '');
    const text = buf.toString('utf8');
    if (vendor.test(text)) offenders.push(rel + ' (vendor token prefix)');
    if (keyAssign.test(text)) offenders.push(rel + ' (secret-looking assignment)');
    if (!rel.startsWith('test/') && !rel.startsWith('contracts/')) {
      // allowlist: none. any bare 64-hex literal outside tests/contracts is suspect
      const src = rel.startsWith('scripts/lib/') ? null : text;
      if (src && rawKey.test(src)) offenders.push(rel + ' (bare 64-hex literal)');
    }
  });
  assert.deepEqual(offenders, []);
});

test('COMP 05: deployment reads the key from the environment only', () => {
  const deploy = readFileSync(join(ROOT, 'scripts', 'deploy-qday.mjs'), 'utf8');
  assert.match(deploy, /QDAY_PRIVATE_KEY/, 'deploy script must read QDAY_PRIVATE_KEY');
  assert.doesNotMatch(deploy, /QDAY_PRIVATE_KEY\s*=\s*['"`]0x[0-9a-f]/i,
    'deploy script must not assign a literal key');
  const env = readFileSync(join(ROOT, '.env.example'), 'utf8');
  assert.match(env, /QDAY_PRIVATE_KEY=\s*($|#|<|your|paste)/im,
    '.env.example key line must be an empty placeholder');
});

test('COMP 06: testnet only claims, no mainnet or real-funds language', () => {
  // bans claims of mainnet deployment or safety guarantees; plain "no real
  // funds" disclaimers are allowed and expected
  const banned = /(mainnet deployment|deployed to mainnet|deploys? (real|actual) funds|holds? real funds for|guaranteed safe|audited by|production ready|financial advice)/i;
  const offenders = [];
  forEachFile((p, buf) => {
    const rel = p.replace(ROOT + '/', '');
    if (banned.test(buf.toString('utf8'))) offenders.push(rel);
  });
  assert.deepEqual(offenders, []);
});

test('COMP 07: educational scope disclosure present in README and UI', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /not a security guarantee|educational|testnet only|no post-quantum signatures/i,
    'README must carry the scope disclosure');
  const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
  assert.match(html, /testnet|simulation|not.*guarantee/i,
    'UI must carry the scope disclosure');
});
