'use strict';

/*
 * Static wiring checks between index.html and the JS modules.
 * Every element id workbench.js binds must exist in the page, the
 * module scripts must load in dependency order, and the error/fetch
 * trackers the headless audit reads must be installed before them.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const workbench = fs.readFileSync(path.join(ROOT, 'src', 'workbench.js'), 'utf8');
const ui = fs.readFileSync(path.join(ROOT, 'src', 'ui.js'), 'utf8');
const styles = fs.readFileSync(path.join(ROOT, 'styles.css'), 'utf8');

test('UI 01: all new modules are loaded by script tags', () => {
  for (const mod of ['pqsig.js', 'attacks.js', 'compare.js', 'receipt.js', 'selftest.js', 'workbench.js']) {
    assert.ok(html.includes('src/' + mod), 'missing script tag for ' + mod);
  }
});

test('UI 02: module scripts load in dependency order', () => {
  const order = ['keccak.js', 'abi.js', 'chain.js', 'risk.js', 'commit.js', 'sim.js',
    'pqsig.js', 'attacks.js', 'compare.js', 'receipt.js', 'selftest.js',
    'rpc.js', 'wallet.js', 'ui.js', 'workbench.js'];
  let last = -1;
  for (const mod of order) {
    const at = html.indexOf('src/' + mod);
    assert.ok(at > last, mod + ' out of order');
    last = at;
  }
});

test('UI 03: pqsig loads before its consumers', () => {
  const pq = html.indexOf('src/pqsig.js');
  for (const consumer of ['attacks.js', 'compare.js', 'receipt.js', 'selftest.js']) {
    assert.ok(html.indexOf('src/' + consumer) > pq, consumer + ' before pqsig');
  }
});

test('UI 04: error and fetch trackers are installed before module scripts', () => {
  const err = html.indexOf('window.__pqpgErrors');
  const firstScript = html.indexOf('src/keccak.js');
  assert.ok(err > 0 && err < firstScript, 'error tracker must precede modules');
});

test('UI 05: every getElementById in workbench has a matching id in html', () => {
  const ids = new Set();
  for (const m of workbench.matchAll(/\$\('([a-z0-9-]+)'\)/g)) ids.add(m[1]);
  const missing = [...ids].filter((id) => !html.includes('id="' + id + '"'));
  assert.deepEqual(missing, [], 'ids missing from index.html: ' + missing.join(', '));
  assert.ok(ids.size >= 20, 'expected 20+ bound ids, got ' + ids.size);
});

test('UI 06: attack cards exist for all six attack ids', () => {
  for (const id of ['replay', 'domain', 'leaf-reuse', 'merkle-tamper', 'shor-drain', 'limit-bypass']) {
    assert.ok(html.includes('data-attack="' + id + '"'), 'missing card ' + id);
    assert.ok(html.includes('data-run-attack="' + id + '"'), 'missing run button ' + id);
  }
});

test('UI 07: nav anchors resolve to section ids', () => {
  for (const href of html.matchAll(/href="#([a-z]+)"/g)) {
    const id = href[1];
    if (id === 'top') continue;
    assert.ok(html.includes('id="' + id + '"'), 'nav target missing: ' + id);
  }
});

test('UI 08: build marker meta tag is present', () => {
  assert.match(html, /pqpg-build/);
});

test('UI 09: selftest report element and hook remain wired', () => {
  assert.ok(html.includes('id="selftest-report"'));
  assert.match(workbench, /selftest-report/);
  assert.match(workbench, /SELFTEST/);
});

test('UI 10: receipt textareas and verify buttons exist', () => {
  for (const id of ['rcpt-payload', 'rcpt-verify-in', 'btn-rcpt-build', 'btn-rcpt-verify',
    'btn-rcpt-tamper', 'btn-rcpt-json', 'btn-rcpt-csv', 'btn-rcpt-md', 'rcpt-checks']) {
    assert.ok(html.includes('id="' + id + '"'), 'missing ' + id);
  }
});

test('UI 11: comparator and budget controls exist', () => {
  for (const id of ['cmp-height', 'compare-body', 'bud-height', 'bud-used', 'bud-rate',
    'budget-bar', 'budget-out', 'budget-warn']) {
    assert.ok(html.includes('id="' + id + '"'), 'missing ' + id);
  }
});

test('UI 12: no external resource references in the page', () => {
  // the headless audit forbids external requests; static check first
  assert.doesNotMatch(html, /src="https?:\/\//);
  assert.doesNotMatch(html, /href="https?:\/\/[^"]*\.(css|js|woff|png)/);
});

test('UI 13: ui.js ids all still resolve (regression)', () => {
  const ids = new Set();
  for (const m of ui.matchAll(/\$\('([a-z0-9-]+)'\)/g)) ids.add(m[1]);
  const missing = [...ids].filter((id) => !html.includes('id="' + id + '"'));
  assert.deepEqual(missing, [], 'ui.js ids missing: ' + missing.join(', '));
});

test('UI 14: decision pipeline section, stage hooks and script order', () => {
  for (const id of ['pipeline', 'pipe-decision', 'pipe-defenses', 'pipe-risk', 'pipe-risk-chip',
    'pipe-cap', 'pipe-cap-chip', 'pipe-escrow', 'pipe-escrow-chip', 'pipe-receipt', 'pipe-receipt-chip']) {
    assert.ok(html.includes('id="' + id + '"'), 'missing ' + id);
  }
  assert.ok(html.indexOf('src/pipeline.js') > html.indexOf('src/workbench.js'), 'pipeline.js must load after workbench.js');
  assert.ok(html.includes('href="#pipeline"'), 'nav link to the pipeline');
  // the state publishers the pipeline reads
  assert.match(ui, /PQPG\.view = \{/);
  assert.match(workbench, /PQPG\.workbench = \{/);
  assert.match(ui, /pqpg:update/);
  assert.match(workbench, /pqpg:update/);
});


test('UI 15: touch target and control contrast regression rules stay pinned', () => {
  assert.match(styles, /button,[\s\S]*?min-width: 44px/);
  assert.match(styles, /button,[\s\S]*?min-height: 44px/);
  assert.match(styles, /\.brand \{[^}]*min-height: 44px/);
  assert.match(styles, /\.head-nav a[\s\S]*?min-height: 44px/);
  assert.match(styles, /a\[rel="noopener"\][^}]*min-width: 44px/);
  assert.match(styles, /\.form input, \.form select, \.net-card input \{[\s\S]*?border: 1px solid var\(--muted\)/);
});

test('UI 16: print stylesheet hides interactive controls and navigation', () => {
  assert.match(styles, /@page \{ margin: 12mm; \}/);
  assert.match(styles, /@media print/);
  assert.match(styles, /nav, button, input, select, textarea[\s\S]*?display: none !important/);
});

test('UI 17: print stylesheet uses light paper and avoids split cards', () => {
  assert.match(styles, /@media print[\s\S]*?background: #fff !important/);
  assert.match(styles, /\[class\*="card" i\][\s\S]*?break-inside: avoid/);
  assert.match(styles, /page-break-inside: avoid/);
});
