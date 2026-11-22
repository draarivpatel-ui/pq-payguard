/*
 * Browser wiring for the workbench panels: attack playground, scheme
 * comparator, key budget planner, signed receipts, scenario bookmarks and
 * the in page self test battery. All heavy logic lives in src/ modules;
 * this file only binds them to the DOM.
 */
(function () {
  'use strict';

  var K = PQPG.keccak;
  var PQ = PQPG.pqsig;
  var AT = PQPG.attacks;
  var CMP = PQPG.compare;
  var RC = PQPG.receipt;
  var ST = PQPG.selftest;

  var $ = function (id) { return document.getElementById(id); };
  var live = $('a11y-live');

  function say(msg) {
    if (live) live.textContent = msg;
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // ---- attack playground -----------------------------------------------------

  var attackResults = {};

  var KIND_MARK = {
    setup: 'ok', info: 'ok', ok: 'ok',
    rejected: 'good', blocked: 'good', protected: 'good',
    compromised: 'bad'
  };

  function renderAttack(res) {
    var card = document.querySelector('.atk-card[data-attack="' + res.id + '"]');
    if (!card) return;
    var v = card.querySelector('[data-verdict]');
    var label = res.verdict + (res.ecdsaVerdict ? ' / ecdsa ' + res.ecdsaVerdict : '');
    v.textContent = label;
    v.className = 'verdict verdict-' + res.verdict.toLowerCase();
    var ol = card.querySelector('.atk-steps');
    ol.innerHTML = res.steps.map(function (s) {
      var mark = KIND_MARK[s.kind] || 'ok';
      return '<li class="st st-' + mark + '">' +
        '<span class="st-label">' + esc(s.label) + '</span>' +
        (s.detail ? '<span class="st-detail">' + esc(s.detail) + '</span>' : '') +
        '</li>';
    }).join('');
    var sum = card.querySelector('.atk-summary');
    if (!sum) {
      sum = document.createElement('p');
      sum.className = 'atk-summary';
      card.insertBefore(sum, card.querySelector('.atk-foot'));
    }
    sum.textContent = res.summary;
  }

  function runAttack(id) {
    var res = AT.runById(id);
    attackResults[id] = res;
    renderAttack(res);
    return res;
  }

  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('button[data-run-attack]');
    if (!b) return;
    try {
      var res = runAttack(b.getAttribute('data-run-attack'));
      say(res.name + ': ' + res.verdict);
    } catch (e) {
      say('Attack run failed: ' + (e && e.message || e));
    }
  });

  function runAllAttacks() {
    var status = $('attacks-status');
    status.textContent = 'running...';
    status.className = 'net-status';
    var results = AT.runAll();
    results.forEach(function (r) {
      attackResults[r.id] = r;
      renderAttack(r);
    });
    status.textContent = results.filter(function (r) {
      return ['REJECTED', 'BLOCKED', 'PROTECTED'].indexOf(r.verdict) !== -1;
    }).length + '/6 defenses held';
    status.className = 'net-status ok';
    say('All six attacks executed');
    return results;
  }

  $('btn-attacks-all').addEventListener('click', runAllAttacks);

  // ---- comparator ------------------------------------------------------------

  function fmtNum(n) {
    return n === null || n === undefined ? 'off-chain' : Number(n).toLocaleString('en-US');
  }

  function renderCompare() {
    var h = Number($('cmp-height').value);
    var rows = CMP.schemeRows(h);
    $('compare-body').innerHTML = rows.map(function (r) {
      return '<tr>' +
        '<td>' + esc(r.name) + '</td>' +
        '<td>' + r.sigBytes.toLocaleString('en-US') + '</td>' +
        '<td>' + r.pkBytes.toLocaleString('en-US') + '</td>' +
        '<td>' + (r.proofBytes ? r.proofBytes + ' B' : '-') + '</td>' +
        '<td>' + (r.hashOpsVerify === null ? 'n/a' : r.hashOpsVerify) + '</td>' +
        '<td>' + r.calldataGas.toLocaleString('en-US') + '</td>' +
        '<td>' + fmtNum(r.execGas) + '</td>' +
        '<td>' + fmtNum(r.onchainGas) + '</td>' +
        '<td><span class="pq-flag ' + (r.pqSecure ? 'yes' : 'no') + '">' + (r.pqSecure ? 'pq' : 'shor') + '</span></td>' +
        '</tr>';
    }).join('');
  }

  $('cmp-height').addEventListener('change', renderCompare);

  // ---- key budget --------------------------------------------------------------

  function renderBudget() {
    try {
      var h = Number($('bud-height').value);
      var used = Number($('bud-used').value || 0);
      var rate = Number($('bud-rate').value || 0);
      var kb = CMP.keyBudget(h, used, rate);
      var bar = $('budget-bar');
      bar.style.width = Math.min(100, kb.pctUsed) + '%';
      bar.className = 'budget-bar lvl-' + kb.level;
      var warn = $('budget-warn');
      if (kb.level === 'critical' || kb.level === 'exhausted') {
        warn.hidden = false;
        warn.textContent = kb.level === 'exhausted'
          ? 'All ' + kb.total + ' leaves consumed. The wallet cannot sign again until the tree is rotated.'
          : 'Only ' + kb.remaining + ' leaves remain. Rotate the merkle root now.';
      } else if (kb.level === 'warn') {
        warn.hidden = false;
        warn.textContent = kb.remaining + ' leaves remain (' + kb.pctUsed + '% used). Plan the next tree rotation.';
      } else {
        warn.hidden = true;
      }
      $('budget-out').innerHTML = [
        ['tree capacity', kb.total.toLocaleString('en-US') + ' one time leaves'],
        ['used', String(kb.used)],
        ['remaining', String(kb.remaining)],
        ['consumed', kb.pctUsed + '%'],
        ['proof size', (h * 32) + ' bytes appended per signature'],
        ['runway', kb.daysLeft === null ? 'no rate given' : '~' + kb.daysLeft + ' days at ' + kb.signsPerDay + ' sig/day']
      ].map(function (p) {
        return '<dt>' + esc(p[0]) + '</dt><dd>' + esc(p[1]) + '</dd>';
      }).join('');
    } catch (e) {
      $('budget-out').innerHTML = '<dt>error</dt><dd>' + esc(e.message) + '</dd>';
      $('budget-warn').hidden = true;
    }
  }

  ['bud-height', 'bud-used', 'bud-rate'].forEach(function (id) {
    $(id).addEventListener('input', renderBudget);
    $(id).addEventListener('change', renderBudget);
  });

  // ---- receipts ------------------------------------------------------------------

  var signWallet = null;
  var lastReceipt = null;
  var lastVerify = null;

  function wallet() {
    if (!signWallet) {
      signWallet = new PQ.HashWallet({
        height: 4, scheme: 'wots', w: 16,
        seed: K.keccak256(K.utf8Bytes('pqpg-receipt-wallet'))
      });
    }
    return signWallet;
  }

  function defaultPayload() {
    var score = {
      scheme: $('in-scheme') ? $('in-scheme').value : 'secp256k1',
      value: $('in-value') ? Number($('in-value').value || 0) : 0,
      ageDays: $('in-age') ? Number($('in-age').value || 0) : 0,
      keyRevealed: $('in-revealed') ? $('in-revealed').checked : false,
      deprecated: $('in-deprecated') ? $('in-deprecated').checked : false
    };
    return {
      scoreInputs: score,
      attacksRun: Object.keys(attackResults),
      verdicts: Object.keys(attackResults).map(function (k) {
        return attackResults[k].id + '=' + attackResults[k].verdict;
      }),
      note: 'deterministic browser simulation, QDay Aevum testnet scope'
    };
  }

  $('rcpt-payload').value = JSON.stringify(defaultPayload(), null, 2);

  function renderChecks(checks) {
    $('rcpt-checks').innerHTML = checks.map(function (c) {
      return '<li class="' + (c.ok ? 'ck-ok' : 'ck-fail') + '">' +
        '<b>' + (c.ok ? 'pass' : 'fail') + '</b> ' + esc(c.name) +
        (c.detail ? ' <span>' + esc(c.detail) + '</span>' : '') + '</li>';
    }).join('');
  }

  $('btn-rcpt-build').addEventListener('click', async function () {
    var status = $('rcpt-status');
    try {
      var payload = JSON.parse($('rcpt-payload').value);
    } catch (e) {
      status.textContent = 'payload is not valid JSON';
      status.className = 'net-status err';
      return;
    }
    status.textContent = 'signing...';
    status.className = 'net-status';
    try {
      var w = wallet();
      var rec = await RC.buildReceipt(payload, {
        wallet: w, chainId: 44005, issuedAt: Math.floor(Date.now() / 1000)
      });
      lastReceipt = rec;
      lastVerify = await RC.verifyReceipt(rec);
      $('rcpt-digest').textContent = rec.digest;
      renderChecks(lastVerify.checks);
      ['btn-rcpt-json', 'btn-rcpt-csv', 'btn-rcpt-md'].forEach(function (id) { $(id).disabled = false; });
      status.textContent = 'signed on wots leaf ' + rec.signature.leafIndex +
        ' (' + w.remaining() + ' leaves left)';
      status.className = 'net-status ok';
      say('Receipt signed and verified');
    } catch (e) {
      status.textContent = String(e && e.message || e);
      status.className = 'net-status err';
    }
  });

  $('btn-rcpt-json').addEventListener('click', function () {
    if (lastReceipt) RC.downloadText('pq-payguard-receipt.json', JSON.stringify(lastReceipt, null, 2), 'application/json');
  });
  $('btn-rcpt-csv').addEventListener('click', function () {
    if (lastReceipt) RC.downloadText('pq-payguard-receipt.csv', RC.receiptToCsv(lastReceipt, lastVerify), 'text/csv');
  });
  $('btn-rcpt-md').addEventListener('click', function () {
    if (lastReceipt) RC.downloadText('pq-payguard-receipt.md', RC.receiptToMarkdown(lastReceipt, lastVerify), 'text/markdown');
  });

  async function verifyTextarea(tamper) {
    var status = $('rcpt-status');
    try {
      var rec = JSON.parse($('rcpt-verify-in').value);
    } catch (e) {
      status.textContent = 'paste a receipt JSON first';
      status.className = 'net-status err';
      return;
    }
    if (tamper) {
      if (rec.body && rec.body.payload && typeof rec.body.payload === 'object') {
        rec.body.payload.__tampered = true;
      } else if (rec.body) {
        rec.body.chainId = (rec.body.chainId || 0) + 1;
      }
    }
    var v = await RC.verifyReceipt(rec);
    renderChecks(v.checks);
    status.textContent = v.ok ? 'receipt verified' : 'verification FAILED' + (tamper ? ' (as expected)' : '');
    status.className = 'net-status ' + (v.ok ? 'ok' : 'err');
    say(v.ok ? 'Receipt verified' : 'Receipt rejected');
  }

  $('btn-rcpt-verify').addEventListener('click', function () { verifyTextarea(false); });
  $('btn-rcpt-tamper').addEventListener('click', function () { verifyTextarea(true); });

  // ---- bookmark -----------------------------------------------------------------

  function currentScenario() {
    return {
      scheme: $('in-scheme').value,
      value: Number($('in-value').value || 0),
      age: Number($('in-age').value || 0),
      revealed: $('in-revealed').checked,
      deprecated: $('in-deprecated').checked
    };
  }

  $('btn-bookmark').addEventListener('click', function () {
    var frag = RC.encodeBookmark(currentScenario());
    $('bookmark-out').textContent = '#' + frag;
    var url = location.origin === 'null' || location.protocol === 'file:'
      ? location.href.split('#')[0] + '#' + frag
      : location.origin + location.pathname + '#' + frag;
    try { history.replaceState(null, '', '#' + frag); } catch (e) { /* file scheme may refuse */ }
    var status = $('bookmark-status');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(function () {
        status.textContent = 'copied';
        status.className = 'net-status ok';
      }, function () { status.textContent = 'built'; });
    } else {
      status.textContent = 'built';
      status.className = 'net-status ok';
    }
    say('Bookmark fragment built');
  });

  // Apply a bookmark on load if present.
  var bookmarkError = null;
  if (location.hash.indexOf('#pq=') === 0) {
    try {
      var sc = RC.decodeBookmark(location.hash);
      if (PQPG.risk.SCHEME_BASE[sc.scheme] !== undefined) $('in-scheme').value = sc.scheme;
      $('in-value').value = String(sc.value);
      $('in-age').value = String(sc.age);
      $('in-revealed').checked = sc.revealed;
      $('in-deprecated').checked = sc.deprecated;
      ['in-scheme', 'in-value', 'in-age', 'in-revealed', 'in-deprecated'].forEach(function (id) {
        $(id).dispatchEvent(new Event('input', { bubbles: true }));
      });
    } catch (e) {
      bookmarkError = String(e && e.message || e);
      var bs = $('bookmark-status');
      bs.textContent = 'bad bookmark: ' + bookmarkError;
      bs.className = 'net-status err';
    }
  }

  // ---- self test battery ----------------------------------------------------------

  async function runSelfTests() {
    var status = $('selftest-status');
    status.textContent = 'running...';
    status.className = 'net-status';
    $('selftest-body').innerHTML = '';
    var sum = await ST.summary();
    $('selftest-body').innerHTML = sum.results.map(function (r) {
      return '<tr><td>' + esc(r.id + ' ' + r.name) + '</td>' +
        '<td class="' + (r.ok ? 'ck-ok' : 'ck-fail') + '">' + (r.ok ? 'pass' : 'FAIL') + '</td>' +
        '<td>' + esc(r.detail) + '</td></tr>';
    }).join('');
    status.textContent = sum.passed + '/' + sum.total + ' passed';
    status.className = 'net-status ' + (sum.failed === 0 ? 'ok' : 'err');
    say('Self tests: ' + sum.passed + ' of ' + sum.total + ' passed');
    return sum;
  }

  $('btn-selftest').addEventListener('click', runSelfTests);

  // ---- boot + selftest hook ---------------------------------------------------------

  renderCompare();
  renderBudget();

  if (/[?&]selftest\b/.test(location.search)) {
    window.addEventListener('load', function () {
      setTimeout(async function () {
        var report = { errors: window.__pqpgErrors || [], fetches: window.__pqpgFetch || [] };
        try {
          report.attacks = runAllAttacks().map(function (r) {
            return { id: r.id, verdict: r.verdict, steps: r.steps.length };
          });
          report.selftest = await runSelfTests();
          report.bookmarkError = bookmarkError;
          report.scrollWidth = document.documentElement.scrollWidth;
          report.innerWidth = window.innerWidth;
          report.overflowX = document.documentElement.scrollWidth > document.documentElement.clientWidth;
        } catch (e) {
          report.errors.push('workbench:' + (e && e.message || e));
        }
        window.__pqpgReport = report;
        var prev = {};
        try { prev = JSON.parse($('selftest-report').textContent || '{}'); } catch (e2) { /* empty */ }
        $('selftest-report').textContent = JSON.stringify(Object.assign(prev, report));
        var failed = (report.selftest ? report.selftest.failed : 1) + report.errors.length;
        document.title = 'SELFTEST ' + (failed === 0 ? 'OK ' + report.selftest.passed + '/' + report.selftest.total : 'FAIL');
      }, 600);
    });
  }
})();
