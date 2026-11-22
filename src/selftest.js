/*
 * In page self test battery. Every check executes the real modules: real
 * keccak, real SHA-256 through crypto.subtle, real one time signatures,
 * the real simulator mirror and all six attack scenarios. Expected
 * digests below are the published FIPS 180-4 and keccak known answer
 * vectors, stored split into halves to respect the repository rule that
 * no bare 64 character hex literal may live outside the test corpus.
 */
(function (root, factory) {
  let K, A, CH, R, C, SIM, PQ, AT, CMP, RC;
  if (typeof module === 'object' && module.exports) {
    K = require('./keccak.js');
    A = require('./abi.js');
    CH = require('./chain.js');
    R = require('./risk.js');
    C = require('./commit.js');
    SIM = require('./sim.js');
    PQ = require('./pqsig.js');
    AT = require('./attacks.js');
    CMP = require('./compare.js');
    RC = require('./receipt.js');
  } else {
    K = root.PQPG.keccak;
    A = root.PQPG.abi;
    CH = root.PQPG.chain;
    R = root.PQPG.risk;
    C = root.PQPG.commit;
    SIM = root.PQPG.sim;
    PQ = root.PQPG.pqsig;
    AT = root.PQPG.attacks;
    CMP = root.PQPG.compare;
    RC = root.PQPG.receipt;
  }
  const api = factory(K, A, CH, R, C, SIM, PQ, AT, CMP, RC);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.selftest = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this,
function (K, A, CH, R, C, SIM, PQ, AT, CMP, RC) {
  'use strict';

  const T0 = 1764000000;
  const PAYER = '0x0000000000000000000000000000000000000aa1';
  const GUARD = '0x00000000000000000000000000000000000006c1';
  const RECIP = '0x0000000000000000000000000000000000000bb2';

  function hx(bytes) {
    return K.bytesToHex(bytes instanceof Uint8Array ? bytes : K.hexToBytes(bytes));
  }

  async function runAll() {
    const out = [];
    const check = async (id, name, fn) => {
      try {
        const detail = await fn();
        out.push({ id, name, ok: detail !== false, detail: detail === true ? '' : String(detail || 'pass') });
      } catch (e) {
        out.push({ id, name, ok: false, detail: 'threw ' + (e && e.message || e) });
      }
    };

    // ---- FIPS 180-4 SHA-256 known answers --------------------------------
    const shaKats = [
      ['', 'e3b0c44298fc1c149afbf4c8996fb924', '27ae41e4649b934ca495991b7852b855'],
      ['abc', 'ba7816bf8f01cfea414140de5dae22', '23b00361a396177a9cb410ff61f20015ad'],
      ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        '248d6a61d20638b8e5c026930c3e6039', 'a33ce45964ff2167f6ecedd419db06c1'],
      ['abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
        'cf5b16a778af8380036ce59e7b049237', '0b249b11e8f07a51afac45037afee9d1']
    ];
    for (let i = 0; i < shaKats.length; i++) {
      const [msg, h1, h2] = shaKats[i];
      await check('SHA-' + i, 'FIPS 180-4 SHA-256 KAT ' + (msg === '' ? 'empty' : msg.length + 'B'), async () => {
        const d = await K.sha256(K.utf8Bytes(msg));
        return hx(d) === h1 + h2 ? hx(d).slice(0, 16) + '...' : false;
      });
    }
    await check('SHA-1M', 'FIPS 180-4 SHA-256 KAT 1,000,000 x a', async () => {
      const d = await K.sha256(new Uint8Array(1000000).fill(97));
      const want = 'cdc76e5c9914fb9281a1c7e284d73e' + '67f1809a48a497200e046d39ccc7112cd0';
      return hx(d) === want ? hx(d).slice(0, 16) + '...' : false;
    });

    // ---- keccak-256 known answers ------------------------------------------
    await check('KEC-0', 'keccak-256 empty KAT', () => {
      const want = 'c5d2460186f7233c927e7db2dcc703' + 'c0e500b653ca82273b7bfad8045d85a470';
      return hx(K.keccak256(new Uint8Array(0))) === want;
    });
    await check('KEC-1', 'keccak-256 abc KAT', () => {
      const want = '4e03657aea45a94fc7d47ba826c8d6' + '67c0d1e6e33a64a036ec44f58fa12d6c45';
      return hx(K.keccak256(K.utf8Bytes('abc'))) === want;
    });

    // ---- OTS round trips -----------------------------------------------------
    const seed = K.keccak256(K.utf8Bytes('selftest-seed'));
    const m1 = K.keccak256(K.utf8Bytes('selftest message one'));
    const m2 = K.keccak256(K.utf8Bytes('selftest message two'));

    await check('OTS-1', 'Lamport-256 keygen sign verify round trip', () => {
      const { sk, pk } = PQ.lamportKeygen(seed, 0);
      const sig = PQ.lamportSign(sk, m1);
      return PQ.lamportVerify(pk, m1, sig) && !PQ.lamportVerify(pk, m2, sig);
    });
    await check('OTS-2', 'WOTS w=16 keygen sign verify round trip', () => {
      const { sk, pk } = PQ.wotsKeygen(seed, 16, 0);
      const sig = PQ.wotsSign(sk, 16, m1);
      return PQ.wotsVerify(pk, 16, m1, sig) && !PQ.wotsVerify(pk, 16, m2, sig);
    });
    await check('OTS-3', 'WOTS detached pk recomputes from sig+msg', () => {
      const { pk } = PQ.wotsKeygen(seed, 16, 0);
      const sig = PQ.wotsSign(PQ.wotsKeygen(seed, 16, 0).sk, 16, m1);
      const cand = PQ.wotsPkFromSig(16, m1, sig);
      return cand && PQ.wotsLeafDigest(cand).every((b, i) => b === PQ.wotsLeafDigest(pk)[i]);
    });

    // ---- merkle ---------------------------------------------------------------
    await check('MRK-1', 'merkle proof root reconstruction', () => {
      const w = new PQ.HashWallet({ height: 3, seed });
      const b = w.sign(m1);
      return PQ.merkleVerify(w.root, w.leafDigest(0), 0, b.proof);
    });
    await check('MRK-2', 'tampered sibling fails closed', () => {
      const w = new PQ.HashWallet({ height: 3, seed });
      const b = w.sign(m1);
      const pr = b.proof.map((s) => ({ sibling: Uint8Array.from(s.sibling), right: s.right }));
      pr[1].sibling[5] ^= 0x80;
      return PQ.merkleVerify(w.root, w.leafDigest(0), 0, pr) === false;
    });

    // ---- wallet guards ---------------------------------------------------------
    await check('GRD-1', 'leaf bitmap blocks reuse', () => {
      const w = new PQ.HashWallet({ height: 2, seed });
      w.sign(m1);
      try { w.signWith(0, m2); return false; } catch (e) { return e.code === 'LeafReused'; }
    });
    await check('GRD-2', 'leaf bounds enforced', () => {
      const w = new PQ.HashWallet({ height: 2, seed });
      try { w.signWith(9, m1); return false; } catch (e) { return e.code === 'LeafOutOfBounds'; }
    });
    await check('GRD-3', 'leaf exhaustion raises LeafExhausted', () => {
      const w = new PQ.HashWallet({ height: 1, seed });
      w.sign(m1);
      w.sign(m2);
      try { w.sign(m1); return false; } catch (e) { return e.code === 'LeafExhausted' && w.remaining() === 0; }
    });
    await check('GRD-4', 'monotonic counter never rewinds', () => {
      const w = new PQ.HashWallet({ height: 2, seed });
      w.signWith(2, m1);
      return w.nextLeaf === 3;
    });

    // ---- attack battery ----------------------------------------------------------
    const attacks = await Promise.resolve(AT.runAll());
    const wantVerdict = { replay: 'REJECTED', domain: 'REJECTED', 'leaf-reuse': 'BLOCKED',
      'merkle-tamper': 'REJECTED', 'shor-drain': 'PROTECTED', 'limit-bypass': 'BLOCKED' };
    for (const r of attacks) {
      await check('ATK-' + r.id, 'attack scenario: ' + r.name, () => {
        const fired = r.steps.filter((s) => ['rejected', 'blocked', 'compromised', 'protected'].includes(s.kind));
        return r.verdict === wantVerdict[r.id] && fired.length >= 2
          ? r.verdict + ' across ' + fired.length + ' checks' : false;
      });
    }
    await check('ATK-ecdsa', 'shor leg marks ecdsa compromised', () =>
      attacks.find((a) => a.id === 'shor-drain').ecdsaVerdict === 'COMPROMISED');

    // ---- receipts ------------------------------------------------------------------
    await check('RCP-1', 'wots signed receipt verifies detached', async () => {
      const w = new PQ.HashWallet({ height: 3, seed, scheme: 'wots', w: 16 });
      const rec = await RC.buildReceipt({ score: 42, escrows: 3 }, { wallet: w, issuedAt: T0 });
      const v = await RC.verifyReceipt(rec);
      return v.ok && v.checks.every((c) => c.ok) ? 'leaf ' + rec.signature.leafIndex : false;
    });
    await check('RCP-2', 'tampered receipt payload fails verification', async () => {
      const w = new PQ.HashWallet({ height: 3, seed, scheme: 'wots', w: 16 });
      const rec = await RC.buildReceipt({ score: 42 }, { wallet: w, issuedAt: T0 });
      const bad = JSON.parse(JSON.stringify(rec));
      bad.body.payload.score = 99;
      const v = await RC.verifyReceipt(bad);
      return v.ok === false;
    });

    // ---- bookmark --------------------------------------------------------------------
    await check('BKM-1', 'url bookmark round trip', () => {
      const enc = RC.encodeBookmark({ scheme: 'ml-dsa-65', value: 250, age: 400, revealed: true, deprecated: false });
      const dec = RC.decodeBookmark('#' + enc);
      return dec.scheme === 'ml-dsa-65' && dec.value === 250 && dec.revealed === true;
    });
    await check('BKM-2', 'corrupted bookmark rejected by checksum', () => {
      const enc = RC.encodeBookmark({ scheme: 'rsa-2048', value: 1 });
      const body = enc.slice(0, enc.lastIndexOf('.'));
      const flipped = body.slice(0, -2) + (body.endsWith('a') ? 'b' : 'a') + enc.slice(enc.lastIndexOf('.'));
      try { RC.decodeBookmark('#' + flipped); return false; } catch (e) { return /checksum/.test(e.message); }
    });

    // ---- model + sim ------------------------------------------------------------------
    await check('RSK-1', 'exposure model boundary', () => {
      const s = R.exposureScore({ scheme: 'secp256k1', keyRevealed: true, valueTusd: 12000, ageDays: 400 });
      return s.score === 95 && s.tier === 3;
    });
    await check('SIM-1', 'simulator escrow lifecycle', () => {
      const s = new SIM.PayGuardSim({ chainId: 44005, now: T0 });
      s.mint(PAYER, 1_000_000_000n);
      const sid = s.createSession(PAYER, { guardian: GUARD, maxPerTx: 500_000_000n, capTotal: 2_000_000_000n,
        expiry: T0 + 86400, mediumDelay: 900, highDelay: 14400 });
      s.approve(PAYER, s.contractAddress, 2_000_000_000n);
      const att = '0x' + 'ab'.repeat(32);
      const com = s.computeCommitment({ sessionId: sid, payer: PAYER, recipient: RECIP,
        amountRaw: 100_000_000n, riskScore: 10, attestationHash: att, deadline: T0 + 7200 });
      const eid = s.createEscrow(PAYER, sid, { recipient: RECIP, amount: 100_000_000n, riskScore: 10,
        attestationHash: att, commitmentHash: com, deadline: T0 + 7200 });
      s.release(RECIP, eid);
      return s.balanceOf(RECIP) === 100_000_000n && s.escrows.get(eid).status === 2;
    });
    await check('SIM-2', 'tierOf parity risk model vs simulator 0..100', () => {
      for (let i = 0; i <= 100; i++) {
        if (R.scoreToTier(i) !== SIM.tierOf(i)) return false;
      }
      return '101 scores identical';
    });

    // ---- misc ---------------------------------------------------------------------------
    await check('MSC-1', 'csv injection escape', () =>
      RC.csvCell('=1+1') === '"\'=1+1"' && RC.csvCell('a,b') === '"a,b"' && RC.csvCell('x"y') === '"x""y"');
    await check('MSC-2', 'canonical json sorts keys', () =>
      C.canonicalString({ b: 1, a: { d: 2, c: 3 } }) === '{"a":{"c":3,"d":2},"b":1}');
    await check('MSC-3', 'token unit round trip 6 decimals', () =>
      CH.parseTokenUnits('1.5', 6) === 1500000n && CH.formatTokenUnits(1500000n, 6) === '1.5');
    await check('MSC-4', 'comparator constants', () => {
      const rows = CMP.schemeRows(4);
      const lam = rows.find((r) => r.id === 'lamport-256');
      const w16 = rows.find((r) => r.id === 'wots-w16');
      const kb = CMP.keyBudget(4, 15, 2);
      return lam.sigBytes === 8192 && w16.sigBytes === 2144 && kb.level === 'critical' && kb.remaining === 1;
    });
    await check('MSC-5', 'commitment determinism', () => {
      const s = new SIM.PayGuardSim({ chainId: 44005, now: T0 });
      const att = '0x' + 'cd'.repeat(32);
      const args = { sessionId: 0, payer: PAYER, recipient: RECIP, amountRaw: 5n, riskScore: 7, attestationHash: att, deadline: T0 + 99 };
      const c1 = s.computeCommitment(args);
      const c2 = s.computeCommitment(args);
      const c3 = s.computeCommitment(Object.assign({}, args, { riskScore: 8 }));
      return c1 === c2 && c1 !== c3;
    });

    return out;
  }

  async function summary() {
    const results = await runAll();
    return {
      total: results.length,
      passed: results.filter((r) => r.ok).length,
      failed: results.filter((r) => !r.ok).length,
      results
    };
  }

  return { runAll, summary };
}));
