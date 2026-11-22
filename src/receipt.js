/*
 * Verification receipts and scenario bookmarks.
 *
 * A receipt is canonical JSON plus a domain separated SHA-256 digest,
 * optionally signed by one WOTS leaf of the demo HashWallet. Because a
 * WOTS public key is a pure function of signature plus message, anyone
 * can verify the receipt detached: recompute the digest, recompute the
 * leaf, walk the merkle proof to the root.
 *
 * The CSV exporter escapes spreadsheet formula injection (leading
 * = + - @ tab CR). The bookmark codec is base64url JSON plus an FNV-1a
 * checksum inside the URL hash fragment, so a scenario link is shareable
 * without any server round trip.
 */
(function (root, factory) {
  let K, C, PQ;
  if (typeof module === 'object' && module.exports) {
    K = require('./keccak.js');
    C = require('./commit.js');
    PQ = require('./pqsig.js');
  } else {
    K = root.PQPG.keccak;
    C = root.PQPG.commit;
    PQ = root.PQPG.pqsig;
  }
  const api = factory(K, C, PQ);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.receipt = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (K, C, PQ) {
  'use strict';

  const RECEIPT_DOMAIN = 'pq-payguard-receipt:';
  const RECEIPT_VERSION = 1;

  // ---- receipt -------------------------------------------------------------

  async function buildReceipt(payload, opts) {
    const o = opts || {};
    const body = {
      v: RECEIPT_VERSION,
      app: 'pq-payguard',
      kind: 'verification-receipt',
      chainId: o.chainId === undefined ? 44005 : o.chainId,
      issuedAt: Number(o.issuedAt === undefined ? Math.floor(Date.now() / 1000) : o.issuedAt),
      payload: payload || {}
    };
    const digest = await K.sha256(K.utf8Bytes(RECEIPT_DOMAIN + C.canonicalString(body)));
    const receipt = { body, digest: '0x' + K.bytesToHex(digest) };
    if (o.wallet) {
      const bundle = o.wallet.sign(digest);
      receipt.signature = {
        scheme: bundle.scheme,
        w: bundle.w,
        leafIndex: bundle.leafIndex,
        merkleRoot: '0x' + K.bytesToHex(o.wallet.root),
        treeHeight: o.wallet.height,
        sig: bundle.sig.map((s) => '0x' + K.bytesToHex(s)),
        proof: bundle.proof.map((p) => ({
          sibling: '0x' + K.bytesToHex(p.sibling),
          right: p.right
        }))
      };
    }
    return receipt;
  }

  /*
   * Verify a receipt object. Recomputes the digest over the canonical
   * body, then - when a signature is attached - recomputes the WOTS leaf
   * from sig+msg and checks the merkle path. Returns a check list so a UI
   * can show exactly which stage failed.
   */
  async function verifyReceipt(receipt) {
    const r = receipt || {};
    const checks = [];
    const push = (name, ok, detail) => checks.push({ name, ok: !!ok, detail: detail || '' });

    if (r.v !== undefined) {
      // tolerate receipts that carry body fields at top level
      if (!r.body) r.body = { v: r.v, app: r.app, kind: r.kind, chainId: r.chainId, issuedAt: r.issuedAt, payload: r.payload };
    }
    const body = r.body;
    push('receipt shape', body && body.kind === 'verification-receipt' && body.v === RECEIPT_VERSION,
      body ? 'kind=' + body.kind + ' v=' + body.v : 'no body');
    if (!body) return { ok: false, checks };

    let digest;
    try {
      digest = await K.sha256(K.utf8Bytes(RECEIPT_DOMAIN + C.canonicalString(body)));
    } catch (e) {
      push('canonical body', false, e.message);
      return { ok: false, checks };
    }
    const digestHex = '0x' + K.bytesToHex(digest);
    push('sha256 digest recomputes', digestHex === String(r.digest || '').toLowerCase(),
      'stored ' + String(r.digest || 'none').slice(0, 18) + '... vs recomputed ' + digestHex.slice(0, 18) + '...');

    if (r.signature) {
      const sig = r.signature;
      let detached = { ok: false, reason: 'malformed signature bundle' };
      try {
        const sigBytes = (sig.sig || []).map((h) => K.hexToBytes(h));
        const proof = (sig.proof || []).map((p) => ({ sibling: K.hexToBytes(p.sibling), right: p.right }));
        detached = PQ.verifyDetached(
          K.hexToBytes(sig.merkleRoot || '0x'),
          digest,
          { leafIndex: sig.leafIndex, scheme: sig.scheme, w: sig.w, sig: sigBytes, proof }
        );
      } catch (e) { /* malformed bundle keeps detached.ok false */ }
      push('one time signature valid', detached.ok,
        detached.ok ? 'leaf ' + sig.leafIndex + ' of height ' + sig.treeHeight : detached.reason);
      push('merkle root anchors the leaf',
        detached.ok && /^0x[0-9a-f]{64}$/.test(String(sig.merkleRoot || '')),
        'root ' + String(sig.merkleRoot || 'none').slice(0, 18) + '...');
    }

    return { ok: checks.every((c) => c.ok), checks };
  }

  // ---- exports ---------------------------------------------------------------

  function downloadText(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  /*
   * CSV escaping that also neutralizes spreadsheet formula injection:
   * quote every field, double inner quotes, and prefix a leading
   * = + - @ tab CR so a hostile cell can never evaluate.
   */
  function csvCell(v) {
    let s = String(v === undefined || v === null ? '' : v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  function toCsv(rows) {
    return rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
  }

  function receiptToCsv(receipt, verifyResult) {
    const b = receipt.body || {};
    const rows = [
      ['field', 'value'],
      ['receipt version', b.v],
      ['application', b.app],
      ['kind', b.kind],
      ['chain id', b.chainId],
      ['issued at', b.issuedAt],
      ['digest', receipt.digest],
      ['signature scheme', receipt.signature ? receipt.signature.scheme : 'unsigned'],
      ['signature leaf', receipt.signature ? receipt.signature.leafIndex : ''],
      ['merkle root', receipt.signature ? receipt.signature.merkleRoot : ''],
      [],
      ['verification check', 'result', 'detail']
    ];
    (verifyResult ? verifyResult.checks : []).forEach((c) => {
      rows.push([c.name, c.ok ? 'pass' : 'FAIL', c.detail]);
    });
    return toCsv(rows);
  }

  function receiptToMarkdown(receipt, verifyResult) {
    const b = receipt.body || {};
    const lines = [
      '# PQ PayGuard verification receipt',
      '',
      '| field | value |',
      '| --- | --- |',
      '| chain id | ' + b.chainId + ' |',
      '| issued at | ' + b.issuedAt + ' |',
      '| digest | `' + receipt.digest + '` |',
      '| signature | ' + (receipt.signature
        ? receipt.signature.scheme + ' leaf ' + receipt.signature.leafIndex + ' under root `' + receipt.signature.merkleRoot + '`'
        : 'unsigned') + ' |',
      ''
    ];
    if (verifyResult) {
      lines.push('| check | result | detail |', '| --- | --- | --- |');
      verifyResult.checks.forEach((c) => {
        lines.push('| ' + c.name + ' | ' + (c.ok ? 'pass' : 'FAIL') + ' | ' + c.detail.replace(/\|/g, '/') + ' |');
      });
      lines.push('');
    }
    return lines.join('\n');
  }

  // ---- bookmark codec --------------------------------------------------------

  function b64urlEncode(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    const b64 = (typeof Buffer !== 'undefined')
      ? Buffer.from(bytes).toString('base64')
      : btoa(bin);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(str) {
    const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (b64.length % 4)) % 4;
    const full = b64 + '='.repeat(pad);
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(full, 'base64'));
    const bin = atob(full);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // FNV-1a 32 bit checksum over the payload string. This is a bookmark
  // integrity check, not a signature; the crypto lives in the receipt.
  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  /*
   * Encode a scenario into '#pq=<b64url>.<fnv1a>'. Fields are whitelisted
   * so a pasted link can only carry display state, never code.
   */
  function encodeBookmark(state) {
    const s = state || {};
    const body = {
      v: 1,
      scheme: String(s.scheme || 'secp256k1'),
      value: Number(s.value || 0),
      age: Number(s.age || 0),
      revealed: !!s.revealed,
      deprecated: !!s.deprecated
    };
    const payload = b64urlEncode(K.utf8Bytes(JSON.stringify(body)));
    return 'pq=' + payload + '.' + fnv1a(payload);
  }

  function decodeBookmark(fragment) {
    let f = String(fragment || '');
    if (f.startsWith('#')) f = f.slice(1);
    if (!f.startsWith('pq=')) throw new Error('not a pq bookmark');
    const rest = f.slice(3);
    const dot = rest.lastIndexOf('.');
    if (dot === -1) throw new Error('bookmark has no checksum');
    const payload = rest.slice(0, dot);
    const crc = rest.slice(dot + 1);
    if (fnv1a(payload) !== crc.toLowerCase()) throw new Error('bookmark checksum mismatch');
    let obj;
    try {
      obj = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
    } catch (e) {
      throw new Error('bookmark payload is not valid JSON');
    }
    if (!obj || obj.v !== 1) throw new Error('unsupported bookmark version');
    return {
      scheme: String(obj.scheme || 'secp256k1'),
      value: Number(obj.value || 0),
      age: Number(obj.age || 0),
      revealed: !!obj.revealed,
      deprecated: !!obj.deprecated
    };
  }

  return {
    RECEIPT_DOMAIN,
    RECEIPT_VERSION,
    buildReceipt,
    verifyReceipt,
    downloadText,
    csvCell,
    toCsv,
    receiptToCsv,
    receiptToMarkdown,
    b64urlEncode,
    b64urlDecode,
    fnv1a,
    encodeBookmark,
    decodeBookmark
  };
}));
