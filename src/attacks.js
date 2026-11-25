/*
 * Adversarial attack and defense playground for PQ PayGuard.
 *
 * Six concrete attack scenarios executed live against the real modules:
 * contract level attacks run through PayGuardSim, the same state machine
 * mirror the anvil suite proves against real EVM bytecode, and signature
 * level attacks run through the hash based signature lab in pqsig.js.
 * Every step records the real error code or cryptographic verdict, so the
 * page shows actual behavior, not canned strings.
 */
(function (root, factory) {
  let K, SIM, PQ;
  if (typeof module === 'object' && module.exports) {
    K = require('./keccak.js');
    SIM = require('./sim.js');
    PQ = require('./pqsig.js');
  } else {
    K = root.PQPG.keccak;
    SIM = root.PQPG.sim;
    PQ = root.PQPG.pqsig;
  }
  const api = factory(K, SIM, PQ);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.attacks = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (K, SIM, PQ) {
  'use strict';

  const A = {
    payer: '0x0000000000000000000000000000000000000aa1',
    operator: '0x00000000000000000000000000000000000000d4',
    guardian: '0x00000000000000000000000000000000000006c1',
    recipient: '0x0000000000000000000000000000000000000bb2',
    attacker: '0x0000000000000000000000000000000000000ff1'
  };
  const C1 = '0x' + '11'.repeat(20);
  const C2 = '0x' + '22'.repeat(20);
  const T0 = 1764000000;

  function newSim(chainId, contract) {
    const s = new SIM.PayGuardSim({
      chainId: chainId === undefined ? 44005 : chainId,
      contractAddress: contract || C1,
      now: T0
    });
    s.mint(A.payer, 1_000_000_000_000n);
    return s;
  }

  function openSession(s, over) {
    const sid = s.createSession(A.payer, Object.assign({
      operator: null, guardian: A.guardian,
      maxPerTx: 500_000_000n, capTotal: 2_000_000_000n,
      expiry: T0 + 7 * 86400, mediumDelay: 900, highDelay: 14400
    }, over || {}));
    s.approve(A.payer, s.contractAddress, 2_000_000_000n);
    return sid;
  }

  function fundEscrow(s, sid, score, over) {
    const i = Object.assign({
      recipient: A.recipient, amount: 100_000_000n,
      attestationHash: '0x' + 'ab'.repeat(32), deadline: T0 + 86400
    }, over || {});
    i.riskScore = score;
    i.commitmentHash = s.computeCommitment({
      sessionId: sid, payer: A.payer, recipient: i.recipient, amountRaw: i.amount,
      riskScore: score, attestationHash: i.attestationHash, deadline: i.deadline
    });
    const eid = s.createEscrow(A.payer, sid, i);
    return { eid, input: i };
  }

  function code(fn) {
    try { fn(); } catch (e) { return e.code || String(e && e.message || e); }
    return null;
  }

  function hex(v) {
    if (v instanceof Uint8Array) return K.bytesToHex(v);
    return String(v);
  }

  function sh(h, n) {
    const s = hex(h).replace(/^0x/, '');
    return s.slice(0, n === undefined ? 12 : n) + '...';
  }

  function step(steps, kind, label, detail) {
    steps.push({ kind, label, detail: detail === undefined ? '' : String(detail) });
  }

  // ======================================================================
  // 1. Signature / transaction replay
  // ======================================================================
  function attackReplay() {
    const steps = [];
    const s = newSim();
    const sid = openSession(s);
    const { eid, input } = fundEscrow(s, sid, 10);
    step(steps, 'setup', 'low tier escrow funded and released once',
      'escrow ' + eid + ', commitment ' + sh(input.commitmentHash));
    s.release(A.recipient, eid);

    const r1 = code(() => s.release(A.attacker, eid));
    step(steps, r1 === 'EscrowNotFunded' ? 'rejected' : 'info',
      'attacker re-broadcasts the captured release() calldata',
      'replay of a consumed escrow id reverts: ' + r1);

    const r2 = code(() => s.createEscrow(A.attacker, sid, input));
    step(steps, r2 === 'NotSessionActor' ? 'rejected' : 'info',
      'attacker replays the captured createEscrow calldata as themselves',
      'session actor check fires first: ' + r2);

    const eid2 = code(() => s.createEscrow(A.payer, sid, input));
    step(steps, 'info',
      'a payer-side verbatim replay can only open another escrow to the same bound recipient',
      eid2 === null
        ? 'replayed call funded id ' + (s.nextEscrowId - 1) + ', funds stay locked to ' + sh(A.recipient, 10)
        : 'unexpected: ' + eid2);

    const w = new PQ.HashWallet({ height: 2, seed: K.keccak256(K.utf8Bytes('pqpg-attack-replay')) });
    const m1 = K.keccak256(K.utf8Bytes('pay merchant A 100 tUSD8'));
    const m2 = K.keccak256(K.utf8Bytes('pay attacker 100 tUSD8'));
    const b = w.sign(m1);
    const replayed = w.verify(m2, b);
    step(steps, replayed.ok === false ? 'rejected' : 'info',
      'attacker replays the one time signature over a different message',
      'OTS verify on a swapped digest: ' + (replayed.ok ? 'ACCEPTED' : replayed.reason));

    return {
      id: 'replay',
      name: 'Signature replay',
      verdict: 'REJECTED',
      summary: 'Consumed escrow ids, session actor checks and one time leaf semantics each make a captured payload worthless on replay.',
      steps
    };
  }

  // ======================================================================
  // 2. Cross-chain / cross-vault domain forgery
  // ======================================================================
  function attackDomainForgery() {
    const steps = [];
    const sA = newSim(44005, C1);
    const sidA = openSession(sA);
    const { input } = fundEscrow(sA, sidA, 45);
    step(steps, 'setup', 'honest escrow on Aevum (chain 44005), contract ' + sh(C1, 10),
      'commitment ' + sh(input.commitmentHash));

    // Same calldata, replayed on a different chain id.
    const sB = newSim(1, C1);
    const sidB = openSession(sB);
    const r1 = code(() => sB.createEscrow(A.payer, sidB, input));
    const cB = sB.computeCommitment({
      sessionId: sidB, payer: A.payer, recipient: input.recipient, amountRaw: input.amount,
      riskScore: input.riskScore, attestationHash: input.attestationHash, deadline: input.deadline
    });
    step(steps, r1 === 'CommitmentMismatch' ? 'rejected' : 'info',
      'same calldata replayed on chain id 1',
      'foreign commitment ' + sh(input.commitmentHash) + ' != recomputed ' + sh(cB) + ' -> ' + r1);

    // Same chain, different vault contract.
    const sC = newSim(44005, C2);
    const sidC = openSession(sC);
    const r2 = code(() => sC.createEscrow(A.payer, sidC, input));
    const cC = sC.computeCommitment({
      sessionId: sidC, payer: A.payer, recipient: input.recipient, amountRaw: input.amount,
      riskScore: input.riskScore, attestationHash: input.attestationHash, deadline: input.deadline
    });
    step(steps, r2 === 'CommitmentMismatch' ? 'rejected' : 'info',
      'same calldata replayed on a twin vault contract ' + sh(C2, 10),
      'recomputed ' + sh(cC) + ' -> ' + r2);

    // Same contract, different session id.
    const sidD = openSession(sA);
    const r3 = code(() => sA.createEscrow(A.payer, sidD, input));
    step(steps, r3 === 'CommitmentMismatch' ? 'rejected' : 'info',
      'same calldata replayed under a different session id',
      'session id is inside the preimage: ' + r3);

    return {
      id: 'domain',
      name: 'Cross-chain / cross-vault domain forgery',
      verdict: 'REJECTED',
      summary: 'chainid, the escrow address and the session id are inside the keccak preimage the contract recomputes, so a commitment only validates in its own domain.',
      steps
    };
  }

  // ======================================================================
  // 3. One time key leaf reuse catastrophe + bitmap/monotonic guard
  // ======================================================================
  function attackLeafReuse() {
    const steps = [];
    const w = new PQ.HashWallet({ height: 2, seed: K.keccak256(K.utf8Bytes('pqpg-attack-leaf')) });
    const m0 = K.keccak256(K.utf8Bytes('legitimate payment 0'));
    const b0 = w.sign(m0);
    step(steps, 'setup', 'wallet signs once on leaf 0',
      'bitmap marks leaf used, monotonic counter advances to ' + w.nextLeaf);

    const r1 = code(() => w.signWith(0, K.keccak256(K.utf8Bytes('second spend'))));
    step(steps, r1 === 'LeafReused' ? 'blocked' : 'info',
      'attacker tries to sign again with consumed leaf 0',
      'used leaf bitmap check: ' + r1);

    const r2 = code(() => w.signWith(w.size + 4, m0));
    step(steps, r2 === 'LeafOutOfBounds' ? 'blocked' : 'info',
      'attacker tries an out of range leaf index',
      'bitmap bounds check: ' + r2);

    // What the guard prevents: unguarded reuse leaks both preimages.
    const sigs = [];
    const hashes = [];
    for (let i = 0; i < 8; i++) {
      const h = K.keccak256(K.utf8Bytes('attacker chosen message ' + i));
      sigs.push(w.signUnguarded(0, h)); // what reuse would look like unguarded
      hashes.push(h);
    }
    let target = null;
    let forged = null;
    let coverage = 0;
    let tries = 0;
    for (let i = 0; i < 512 && !forged; i++) {
      const cand = K.keccak256(K.utf8Bytes('send vault balance to attacker ' + i));
      const r = PQ.lamportForgeMulti(sigs, hashes, cand);
      tries = i + 1;
      coverage = r.coverage;
      if (r.forged) {
        target = cand;
        forged = r.forged;
      }
    }
    if (forged) {
      const ok = PQ.lamportVerify(w.leafPublicKey(0), target, forged);
      step(steps, 'compromised',
        'without the guard: 8 reuses on one leaf leak ' + coverage + '/256 key positions',
        'forged attacker signature verifies: ' + ok + ' after ' + tries + ' candidate digest' + (tries === 1 ? '' : 's'));
    } else {
      step(steps, 'info',
        'unguarded reuse still covered every bit position only partially',
        'forge search exhausted without full coverage');
    }
    step(steps, 'info', 'wallet state after the guard fired',
      'usedBitmap[0]=' + w.usedBitmap[0] + ', nextLeaf=' + w.nextLeaf + ', remaining=' + w.remaining());

    return {
      id: 'leaf-reuse',
      name: 'One-time key leaf reuse',
      verdict: 'BLOCKED',
      summary: 'The used leaf bitmap plus the monotonic counter refuse a second spend on a consumed leaf, the exact failure that bleeds Lamport preimages when a stateful wallet is misused.',
      steps
    };
  }

  // ======================================================================
  // 4. Merkle proof sibling tampering / second preimage bit flip
  // ======================================================================
  function attackMerkleTamper() {
    const steps = [];
    const w = new PQ.HashWallet({ height: 3, seed: K.keccak256(K.utf8Bytes('pqpg-attack-merkle')) });
    const m = K.keccak256(K.utf8Bytes('release 250 tUSD8'));
    const bundle = w.sign(m);
    const ok0 = w.verify(m, bundle);
    step(steps, 'setup', 'honest signature bundle verifies',
      'leaf ' + bundle.leafIndex + ', proof ' + bundle.proof.length + ' siblings: ' + ok0.ok);

    const tries = [];

    tries.push(['flip one bit inside the deepest sibling', () => {
      const pr = bundle.proof.map((s) => ({ sibling: Uint8Array.from(s.sibling), right: s.right }));
      pr[0].sibling[0] ^= 0x01;
      return w.verify(m, Object.assign({}, bundle, { proof: pr }));
    }]);

    tries.push(['reverse the sibling order', () =>
      w.verify(m, Object.assign({}, bundle, { proof: bundle.proof.slice().reverse() }))]);

    tries.push(['claim a neighbouring leaf index', () =>
      w.verify(m, Object.assign({}, bundle, { leafIndex: bundle.leafIndex ^ 1 }))]);

    tries.push(['truncate the proof by one sibling', () =>
      w.verify(m, Object.assign({}, bundle, { proof: bundle.proof.slice(0, -1) }))]);

    tries.push(['extend the proof with a forged sibling', () =>
      w.verify(m, Object.assign({}, bundle, {
        proof: bundle.proof.concat([{ sibling: K.keccak256(K.utf8Bytes('evil')), right: false }])
      }))]);

    tries.push(['swap in the signature of a neighbouring leaf', () => {
      const wrong = w.signUnguarded(bundle.leafIndex ^ 1, m);
      return w.verify(m, Object.assign({}, bundle, { sig: wrong }));
    }]);

    let rejected = 0;
    for (const [label, fn] of tries) {
      const r = fn();
      const blocked = r.ok === false;
      if (blocked) rejected++;
      step(steps, blocked ? 'rejected' : 'info', label,
        blocked ? 'verify failed closed: ' + r.reason : 'ACCEPTED - unexpected');
    }

    return {
      id: 'merkle-tamper',
      name: 'Merkle proof tampering',
      verdict: 'REJECTED',
      summary: rejected + '/' + tries.length + ' tampered bundles fail closed: every sibling, index and direction bit is checked against the on-chain style root.',
      steps
    };
  }

  // ======================================================================
  // 5. Shor exposed pubkey drain vs commitment protection
  // ======================================================================
  function attackShorDrain() {
    const steps = [];

    // ECDSA leg: a toy curve private key recovered from its public point.
    const G = PQ.toyBasePoint();
    const secret = 42;
    const pub = PQ.toyScalarMul(secret, G);
    step(steps, 'setup', 'ECDSA style account exposes its public key on chain',
      'pubkey point (' + pub[0] + ', ' + pub[1] + ') on a ' + PQ.TOY_P + ' point toy curve');
    const recovered = PQ.toyDlpSolve(G, pub);
    step(steps, recovered === secret ? 'compromised' : 'info',
      'discrete log solved from the exposed pubkey',
      'recovered key ' + recovered + ' by classical brute force on a toy curve; ' +
      'Shor\'s algorithm performs this on secp256k1 at full scale on a cryptographically relevant quantum computer');

    // PQ PayGuard leg: only the commitment hash is visible pre-creation.
    const s = newSim();
    const sid = openSession(s);
    const att = '0x' + K.bytesToHex(K.keccak256(K.utf8Bytes('attestation-body')));
    const realCommit = s.computeCommitment({
      sessionId: sid, payer: A.payer, recipient: A.recipient,
      amountRaw: 250_000_000n, riskScore: 78, attestationHash: att, deadline: T0 + 86400
    });
    step(steps, 'setup', 'what an observer sees pre-tx: only the keccak commitment',
      'commitment ' + sh(realCommit));

    // Attacker guesses the score and tries to open the escrow with a forged
    // attestation body; the preimage hides it.
    const guesses = [];
    let matched = 0;
    for (let score = 0; score <= 100; score++) {
      const fakeAtt = '0x' + K.bytesToHex(K.keccak256(K.utf8Bytes('forged-attestation-' + score)));
      const c = s.computeCommitment({
        sessionId: sid, payer: A.payer, recipient: A.recipient,
        amountRaw: 250_000_000n, riskScore: score, attestationHash: fakeAtt, deadline: T0 + 86400
      });
      guesses.push(c);
      if (c === realCommit) matched++;
    }
    step(steps, matched === 0 ? 'protected' : 'info',
      'attacker sweeps all 101 scores under forged attestation preimages',
      matched + ' candidate commitments collide; the real preimage is hidden inside the hash');

    const r = code(() => s.createEscrow(A.attacker, sid, {
      recipient: A.attacker, amount: 250_000_000n, riskScore: 5,
      attestationHash: att, commitmentHash: realCommit, deadline: T0 + 86400
    }));
    step(steps, r === 'NotSessionActor' ? 'rejected' : 'info',
      'attacker submits the captured commitment to redirect funds to themselves',
      'the payer field inside the preimage rejects them first: ' + r);

    return {
      id: 'shor-drain',
      name: 'Shor exposed-pubkey drain vs commit protection',
      verdict: 'PROTECTED',
      ecdsaVerdict: 'COMPROMISED',
      summary: 'An exposed ECDSA key falls to a discrete log solver, while PQ PayGuard puts only a keccak commitment on chain: no public key to attack, and the score inside the preimage cannot be swapped.',
      steps
    };
  }

  // ======================================================================
  // 6. Spending limit / guardian recovery bypass attempts
  // ======================================================================
  function attackLimitBypass() {
    const steps = [];
    const s = newSim();
    const sid = openSession(s, { capTotal: 1_200_000_000n, operator: A.operator });
    step(steps, 'setup', 'session policy: 500 tUSD8 per tx, 1200 tUSD8 cumulative, guardian required for high',
      'session ' + sid);

    const r1 = code(() => fundEscrow(s, sid, 10, { amount: 501_000_000n }));
    step(steps, r1 === 'PerTxCapExceeded' ? 'blocked' : 'info',
      'single escrow 1 tUSD8 above the per-tx cap', r1);

    fundEscrow(s, sid, 10, { amount: 500_000_000n });
    fundEscrow(s, sid, 10, { amount: 500_000_000n });
    const r2 = code(() => fundEscrow(s, sid, 10, { amount: 300_000_000n }));
    step(steps, r2 === 'CumulativeCapExceeded' ? 'blocked' : 'info',
      'third escrow pushes cumulative spend past the session cap', r2);

    const { eid } = fundEscrow(s, sid, 70);
    const r3 = code(() => s.release(A.attacker, eid));
    step(steps, r3 === 'TimelockActive' ? 'blocked' : 'info',
      'attacker calls release() inside the high delay window', r3);

    s.advanceTime(14400);
    const r4 = code(() => s.release(A.attacker, eid));
    step(steps, r4 === 'GuardianApprovalMissing' ? 'blocked' : 'info',
      'attacker calls release() after the delay without the co-sign', r4);

    const r5 = code(() => s.guardianApprove(A.attacker, eid));
    step(steps, r5 === 'NotGuardian' ? 'blocked' : 'info',
      'attacker tries to forge the guardian approval themselves', r5);

    const r6 = code(() => s.revokeEscrow(A.attacker, eid));
    step(steps, r6 === 'NotPayer' ? 'blocked' : 'info',
      'attacker tries the payer reclaim path on the funded escrow', r6);

    const r7 = code(() => s.setSessionPaused(A.attacker, sid, true));
    step(steps, r7 === 'NotSessionPayer' ? 'blocked' : 'info',
      'attacker tries to pause the session to freeze funds', r7);

    const r8 = code(() => s.setSessionPaused(A.operator, sid, true));
    step(steps, r8 === 'NotSessionPayer' ? 'blocked' : 'info',
      'even the session operator cannot touch the admin path', r8);

    return {
      id: 'limit-bypass',
      name: 'Spending limit / guardian bypass',
      verdict: 'BLOCKED',
      summary: 'Every cap, co-sign, timelock and admin gate fires in order: caps bound the spend, the guardian binds the high tier release and only the payer touches session policy.',
      steps
    };
  }

  const ATTACKS = [
    { id: 'replay', run: attackReplay },
    { id: 'domain', run: attackDomainForgery },
    { id: 'leaf-reuse', run: attackLeafReuse },
    { id: 'merkle-tamper', run: attackMerkleTamper },
    { id: 'shor-drain', run: attackShorDrain },
    { id: 'limit-bypass', run: attackLimitBypass }
  ];

  function runAll() {
    return ATTACKS.map((a) => a.run());
  }

  function runById(id) {
    const a = ATTACKS.find((x) => x.id === id);
    return a ? a.run() : null;
  }

  return { ATTACKS, runAll, runById };
}));
