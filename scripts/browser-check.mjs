#!/usr/bin/env node
/*
 * Zero-dependency headless Chromium audit for PQ PayGuard.
 *
 * Launches real Chrome (--headless=new, throwaway profile), drives it over
 * raw CDP through Node's built in WebSocket, and asserts at desktop, tablet
 * and phone viewports:
 *
 *   - 0 console errors, 0 uncaught page errors
 *   - 0 external network requests (everything served from 127.0.0.1)
 *   - 0 horizontal overflow (scrollWidth <= clientWidth)
 *   - all 6 attack demos run and hold their verdicts
 *   - scheme comparator re-renders across merkle heights
 *   - key budget planner warns at critical levels
 *   - self-test battery runs and passes inside the page
 *   - signed receipt builds, verifies, and a tampered copy fails
 *   - bookmark fragment builds with a valid checksum
 *
 * Usage: node scripts/browser-check.mjs [--chrome PATH] [--keep]
 */

import { spawn, execFileSync } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHROME = process.argv.includes('--chrome')
  ? process.argv[process.argv.indexOf('--chrome') + 1]
  : '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const KEEP = process.argv.includes('--keep');
const ORIGIN_PORT = 4399 + (process.pid % 211);

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png',
  '.md': 'text/markdown', '.ico': 'image/x-icon'
};

// ---------- tiny static server ---------------------------------------------

function serve() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let p = decodeURIComponent((req.url || '/').split('?')[0]);
      if (p === '/') p = '/index.html';
      const file = path.join(ROOT, p);
      if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        res.writeHead(404); res.end('nf'); return;
      }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      fs.createReadStream(file).pipe(res);
    });
    srv.listen(ORIGIN_PORT, '127.0.0.1', () => resolve(srv));
  });
}

// ---------- minimal CDP client ----------------------------------------------

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (p) { this.pending.delete(msg.id); msg.error ? p.rej(new Error(msg.error.message)) : p.res(msg.result); }
      } else {
        const hs = this.handlers.get(msg.method);
        if (hs) hs.forEach((f) => f(msg.params));
      }
    });
  }
  static connect(url) {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.addEventListener('open', () => resolve(new Cdp(ws)));
      ws.addEventListener('error', (e) => reject(new Error('ws connect failed')));
      setTimeout(() => reject(new Error('ws connect timeout')), 10000);
    });
  }
  send(method, params) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      this.pending.set(id, { res, rej });
      this.ws.send(JSON.stringify({ id, method, params: params || {} }));
    });
  }
  on(method, fn) {
    if (!this.handlers.has(method)) this.handlers.set(method, []);
    this.handlers.get(method).push(fn);
  }
  async eval(expr, awaitPromise) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr, returnByValue: true, awaitPromise: !!awaitPromise
    });
    if (r.exceptionDetails) {
      const ex = r.exceptionDetails.exception;
      throw new Error('eval failed: ' + (ex && ex.description || r.exceptionDetails.text).slice(0, 400));
    }
    return r.result ? r.result.value : undefined;
  }
}

// ---------- chrome launch ----------------------------------------------------

async function launchChrome(url, width, height) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'pqpg-chrome-'));
  const args = [
    '--headless=new', '--mute-audio', '--disable-gpu',
    '--remote-debugging-port=0',
    '--user-data-dir=' + profile,
    '--no-first-run', '--no-default-browser-check',
    '--window-size=' + width + ',' + height,
    url
  ];
  const proc = spawn(CHROME, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d; });
  const portFile = path.join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100; i++) {
    if (fs.existsSync(portFile)) {
      const [port] = fs.readFileSync(portFile, 'utf8').split('\n');
      return { proc, port: Number(port), profile };
    }
    if (proc.exitCode !== null) throw new Error('chrome exited: ' + stderr.slice(-400));
    await new Promise((r) => setTimeout(r, 100));
  }
  proc.kill('SIGKILL');
  throw new Error('no DevToolsActivePort: ' + stderr.slice(-400));
}

async function pageTarget(port) {
  for (let i = 0; i < 50; i++) {
    try {
      const list = JSON.parse(execFileSync('curl', ['-s', `http://127.0.0.1:${port}/json/list`], { encoding: 'utf8' }));
      const page = list.find((t) => t.type === 'page');
      if (page) return page;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('no page target');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- the audit ----------------------------------------------------------

const checks = [];
function check(name, ok, detail) {
  checks.push({ name, ok: !!ok, detail: detail || '' });
  console.log(`  ${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ' - ' + detail : ''}`);
}

async function auditViewport(width, height, baseUrl) {
  const local = `http://127.0.0.1:${ORIGIN_PORT}`;
  const { proc, port, profile } = await launchChrome(`${local}/index.html?selftest`, width, height);
  const tag = `${width}x${height}`;
  console.log(`\n=== viewport ${tag} ===`);
  const consoleErrors = [];
  const pageErrors = [];
  const external = [];
  try {
    const target = await pageTarget(port);
    const cdp = await Cdp.connect(target.webSocketDebuggerUrl);
    cdp.on('Runtime.consoleAPICalled', (p) => {
      if (['error', 'assert'].includes(p.type)) {
        consoleErrors.push((p.args || []).map((a) => a.value || a.description || '').join(' '));
      }
    });
    cdp.on('Runtime.exceptionThrown', (p) => {
      const d = p.exceptionDetails;
      pageErrors.push((d.exception && d.exception.description || d.text || '').split('\n')[0]);
    });
    cdp.on('Network.requestWillBeSent', (p) => {
      const u = p.request.url;
      if (!u.startsWith(local) && !u.startsWith('data:') && !u.startsWith('blob:')) {
        external.push(u);
      }
    });
    await cdp.send('Runtime.enable');
    await cdp.send('Page.enable');
    await cdp.send('Network.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width, height, deviceScaleFactor: 1, mobile: width < 600
    });
    await cdp.send('Page.navigate', { url: `${local}/index.html?selftest` });

    // wait for the workbench selftest report (heavy crypto, poll generously)
    let report = null;
    for (let i = 0; i < 300 && !report; i++) {
      await sleep(500);
      try {
        report = await cdp.eval('window.__pqpgReport && window.__pqpgReport.selftest ? JSON.stringify(window.__pqpgReport) : null');
        if (report) report = JSON.parse(report);
      } catch { /* page still booting */ }
    }
    if (!report) {
      check(`${tag} selftest report produced`, false, 'timeout waiting for __pqpgReport');
      return;
    }

    // ---- core hygiene
    check(`${tag} zero console errors`, consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '));
    check(`${tag} zero uncaught page errors`, pageErrors.length === 0, pageErrors.slice(0, 2).join(' | '));
    check(`${tag} zero external requests`, external.length === 0, external.slice(0, 2).join(' | '));
    const overflow = await cdp.eval('document.documentElement.scrollWidth > document.documentElement.clientWidth');
    check(`${tag} no horizontal overflow`, !overflow,
      await cdp.eval('document.documentElement.scrollWidth + " vs " + document.documentElement.clientWidth'));
    check(`${tag} report has no page errors`, (report.errors || []).length === 0, (report.errors || []).slice(0, 2).join(' | '));
    check(`${tag} report has no fetches`, (report.fetches || []).length === 0);

    // ---- attack demos
    const expectedVerdicts = {
      'replay': 'REJECTED', 'domain': 'REJECTED', 'leaf-reuse': 'BLOCKED',
      'merkle-tamper': 'REJECTED', 'shor-drain': 'PROTECTED', 'limit-bypass': 'BLOCKED'
    };
    const atk = report.attacks || [];
    check(`${tag} all six attacks ran`, atk.length === 6, atk.map((a) => a.id).join(','));
    for (const [id, want] of Object.entries(expectedVerdicts)) {
      const a = atk.find((x) => x.id === id);
      check(`${tag} attack ${id} verdict ${want}`, a && a.verdict === want, a ? a.verdict : 'missing');
    }
    // and the rendered UI carries the verdicts
    const domVerdicts = await cdp.eval(`JSON.stringify(
      [...document.querySelectorAll('.atk-card')].map(c => ({
        id: c.getAttribute('data-attack'),
        v: c.querySelector('[data-verdict]').textContent.trim(),
        steps: c.querySelectorAll('.atk-steps li').length
      })))`);
    for (const c of JSON.parse(domVerdicts || '[]')) {
      check(`${tag} card ${c.id} shows steps`, c.steps >= 4, c.steps + ' steps, ' + c.v);
    }

    // ---- self test battery
    const st = report.selftest;
    check(`${tag} selftest battery all pass`, st.failed === 0, `${st.passed}/${st.total}`);
    check(`${tag} selftest count >= 30`, st.total >= 30, String(st.total));
    const stRows = await cdp.eval(`document.querySelectorAll('#selftest-body tr').length`);
    check(`${tag} selftest table rendered`, stRows === st.total, stRows + ' rows');
    check(`${tag} title reports SELFTEST OK`, (await cdp.eval('document.title')).startsWith('SELFTEST OK'),
      await cdp.eval('document.title'));

    // ---- comparator
    await cdp.eval(`document.getElementById('cmp-height').value = '10';
      document.getElementById('cmp-height').dispatchEvent(new Event('change'))`);
    const rows10 = await cdp.eval(`document.querySelectorAll('#compare-body tr').length`);
    const lamportCell = await cdp.eval(
      `[...document.querySelectorAll('#compare-body tr')][0].children[3].textContent`);
    check(`${tag} comparator renders all scheme rows`, rows10 === 13, rows10 + ' rows');
    check(`${tag} comparator proof bytes track height`, lamportCell.trim() === '320 B', lamportCell);
    await cdp.eval(`document.getElementById('cmp-height').value = '8';
      document.getElementById('cmp-height').dispatchEvent(new Event('change'))`);

    // ---- key budget
    await cdp.eval(`document.getElementById('bud-used').value = '250';
      document.getElementById('bud-used').dispatchEvent(new Event('input'))`);
    const warn = await cdp.eval(`document.getElementById('budget-warn').textContent`);
    const warnShown = await cdp.eval(`!document.getElementById('budget-warn').hidden`);
    check(`${tag} budget warns near exhaustion`, warnShown && /leaves remain|consumed/i.test(warn), warn.slice(0, 60));
    const barPct = await cdp.eval(`document.getElementById('budget-bar').style.width`);
    check(`${tag} budget bar tracks usage`, /9\d(\.\d)?%/.test(barPct), barPct);

    const batchSetup = await cdp.eval(`(() => {
      const v = PQPG.view;
      const sim = v.sim;
      const payer = v.actors.payer;
      const recipient = v.actors.recipient;
      const guardian = v.actors.guardian;
      const att = '0x' + 'ab'.repeat(32);
      const amount = 100000n;
      const sid = sim.createSession(payer, {
        operator: null, guardian,
        maxPerTx: 500000n, capTotal: 2000000n,
        expiry: sim.now + 86400, mediumDelay: 900, highDelay: 14400
      });
      sim.approve(payer, sim.contractAddress, 2000000n);
      const deadline = sim.now + 86400;
      const com = sim.computeCommitment({
        sessionId: sid, payer, recipient, amountRaw: amount,
        riskScore: 10, attestationHash: att, deadline
      });
      sim.createEscrow(payer, sid, {
        recipient, amount, riskScore: 10,
        attestationHash: att, commitmentHash: com, deadline
      });
      document.getElementById('btn-warp').click();
      return {
        disabled: document.getElementById('btn-batch-rescue').disabled,
        label: document.getElementById('btn-batch-rescue').textContent
      };
    })()`);
    check(`${tag} batch rescue starts enabled for payer`, batchSetup && batchSetup.disabled === false,
      batchSetup ? batchSetup.label : 'setup failed');
    const guardianBatch = await cdp.eval(`(() => {
      const sel = document.getElementById('sim-actor');
      sel.value = PQPG.view.actors.guardian;
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      const btn = document.getElementById('btn-batch-rescue');
      return { disabled: btn.disabled, label: btn.textContent };
    })()`);
    check(`${tag} batch rescue disables when acting as guardian`, guardianBatch.disabled === true,
      guardianBatch.label);
    const payerBatch = await cdp.eval(`(() => {
      const sel = document.getElementById('sim-actor');
      sel.value = PQPG.view.actors.payer;
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      const btn = document.getElementById('btn-batch-rescue');
      return { disabled: btn.disabled, label: btn.textContent };
    })()`);
    check(`${tag} batch rescue re-enables when acting as payer`, payerBatch.disabled === false,
      payerBatch.label);

    // ---- receipt lifecycle
    await cdp.eval(`document.getElementById('btn-rcpt-build').click()`);
    let digest = null;
    for (let i = 0; i < 80 && !digest; i++) {
      await sleep(250);
      const d = await cdp.eval(`document.getElementById('rcpt-digest').textContent`);
      if (/^0x[0-9a-f]{64}$/.test(d)) digest = d;
    }
    check(`${tag} receipt builds and signs`, !!digest, digest ? digest.slice(0, 18) + '...' : 'no digest');
    const checksCount = await cdp.eval(`document.querySelectorAll('#rcpt-checks li').length`);
    check(`${tag} receipt verifies inline`, checksCount >= 4, checksCount + ' checks');
    const rcptJson = await cdp.eval(`(async () => {
      const btn = document.getElementById('btn-rcpt-json');
      return btn.disabled ? null : 'enabled';
    })()`, true);
    check(`${tag} export buttons unlock after signing`, rcptJson === 'enabled');

    // grab the receipt json for the tamper check: rebuild via the module directly
    const tampered = await cdp.eval(`(async () => {
      const RC = PQPG.receipt, PQ = PQPG.pqsig, K = PQPG.keccak;
      const w = new PQ.HashWallet({ height: 3, scheme: 'wots', w: 16, seed: K.keccak256(K.utf8Bytes('pqpg-receipt-wallet')) });
      const rec = await RC.buildReceipt({ score: 55 }, { wallet: w, chainId: 44005 });
      rec.body.payload.score = 999;
      document.getElementById('rcpt-verify-in').value = JSON.stringify(rec);
      document.getElementById('btn-rcpt-verify').click();
      return 'sent';
    })()`, true);
    await sleep(1200);
    const verifyStatus = await cdp.eval(`document.getElementById('rcpt-status').textContent`);
    check(`${tag} tampered receipt fails verification`, /FAILED/i.test(verifyStatus), verifyStatus);

    // ---- bookmark
    await cdp.eval(`document.getElementById('btn-bookmark').click()`);
    await sleep(300);
    const frag = await cdp.eval(`document.getElementById('bookmark-out').textContent`);
    check(`${tag} bookmark fragment built`, /^#pq=[A-Za-z0-9_-]+\.[0-9a-f]{8}$/.test(frag), frag.slice(0, 40));

    // ---- bookmark decode inside the page
    const decOk = await cdp.eval(`(() => {
      try {
        const d = PQPG.receipt.decodeBookmark(${JSON.stringify(frag)});
        return d && typeof d.scheme === 'string';
      } catch (e) { return 'ERR:' + e.message; }
    })()`);
    check(`${tag} bookmark decodes in page`, decOk === true, String(decOk));

    // ---- late error sweep (catches errors raised by the interactions above)
    check(`${tag} still zero console errors after interactions`, consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '));
    check(`${tag} still zero page errors after interactions`, pageErrors.length === 0, pageErrors.slice(0, 2).join(' | '));
    check(`${tag} still zero external requests after interactions`, external.length === 0, external.slice(0, 2).join(' | '));

    cdp.ws.close();
  } finally {
    proc.kill('SIGKILL');
    if (!KEEP) try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

const srv = await serve();
try {
  await auditViewport(1440, 900);
  await auditViewport(820, 1180);
  await auditViewport(390, 844);
} finally {
  srv.close();
}

const passed = checks.filter((c) => c.ok).length;
const failed = checks.filter((c) => !c.ok);
console.log(`\n==== browser audit: ${passed}/${checks.length} checks passed ====`);
if (failed.length) {
  failed.forEach((f) => console.log('FAILED: ' + f.name + ' - ' + f.detail));
  process.exit(1);
}
