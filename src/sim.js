/*
 * PayGuardSim: a deterministic, dependency free mirror of the
 * PQPayGuardEscrow state machine plus a minimal token ledger. The browser
 * simulator and the parity tests both drive this; every revert condition and
 * error name matches the Solidity contract branch for branch.
 */
(function (root, factory) {
  let C;
  if (typeof module === 'object' && module.exports) {
    C = require('./commit.js');
  } else {
    C = root.PQPG.commit;
  }
  const api = factory(C);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.PQPG = root.PQPG || {};
    root.PQPG.sim = api;
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function (C) {
  'use strict';

  const ZERO = '0x0000000000000000000000000000000000000000';
  const MAX_DELAY = 30 * 24 * 3600;

  class SimError extends Error {
    constructor(code, detail) {
      super(code + (detail !== undefined ? '(' + detail + ')' : ''));
      this.name = 'SimError';
      this.code = code;
      this.detail = detail;
    }
  }

  function fail(code, detail) {
    throw new SimError(code, detail);
  }

  function addr(a) {
    if (typeof a !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(a)) {
      throw new TypeError('invalid address: ' + a);
    }
    return '0x' + a.slice(2).toLowerCase();
  }

  function tierOf(score) {
    if (!Number.isInteger(score) || score < 0 || score > 100) fail('InvalidScore');
    if (score <= 29) return 0;
    if (score <= 59) return 1;
    if (score <= 84) return 2;
    return 3;
  }

  /*
   * opts: { chainId, contractAddress, now }
   * contractAddress is used inside computeCommitment, mirroring address(this).
   */
  class PayGuardSim {
    constructor(opts) {
      const o = opts || {};
      this.chainId = BigInt(o.chainId === undefined ? 44005 : o.chainId);
      this.contractAddress = o.contractAddress
        ? addr(o.contractAddress)
        : '0x' + '11'.repeat(20);
      this.now = Math.floor(o.now === undefined ? 1700000000 : o.now);
      this.sessions = new Map();
      this.escrows = new Map();
      this.nextSessionId = 0;
      this.nextEscrowId = 0;
      this.audit = [];
      this.balances = new Map();      // token ledger: address -> BigInt
      this.allowances = new Map();    // owner -> spender -> BigInt
    }

    _log(name, fields) {
      this.audit.push(Object.assign({ event: name, at: this.now }, fields));
    }

    setTime(t) {
      const n = Number(t);
      if (!Number.isSafeInteger(n)) throw new TypeError('time must be a safe integer');
      this.now = n;
    }
    advanceTime(seconds) {
      const n = Number(seconds);
      if (!Number.isSafeInteger(n)) throw new TypeError('seconds must be a safe integer');
      this.now += n;
    }

    mint(to, amount) {
      const a = addr(to);
      const v = BigInt(amount);
      this.balances.set(a, (this.balances.get(a) || 0n) + v);
      this._log('Transfer', { from: ZERO, to: a, amount: v.toString() });
    }

    balanceOf(a) {
      return this.balances.get(addr(a)) || 0n;
    }

    approve(owner, spender, amount) {
      const o = addr(owner);
      const s = addr(spender);
      let inner = this.allowances.get(o);
      if (!inner) { inner = new Map(); this.allowances.set(o, inner); }
      inner.set(s, BigInt(amount));
      this._log('Approval', { owner: o, spender: s, amount: BigInt(amount).toString() });
    }

    allowance(owner, spender) {
      const inner = this.allowances.get(addr(owner));
      return (inner && inner.get(addr(spender))) || 0n;
    }

    _session(id) {
      const s = this.sessions.get(Number(id));
      if (!s) fail('SessionUnknown');
      return s;
    }

    _escrow(id) {
      const e = this.escrows.get(Number(id));
      if (!e) fail('EscrowUnknown');
      return e;
    }

    createSession(caller, input) {
      const i = input || {};
      const payer = addr(caller);
      const operator = i.operator ? addr(i.operator) : ZERO;
      const guardian = i.guardian ? addr(i.guardian) : ZERO;
      const maxPerTx = BigInt(i.maxPerTx);
      const capTotal = BigInt(i.capTotal);
      const expiryRaw = Number(i.expiry);
      const mediumRaw = Number(i.mediumDelay);
      const highRaw = Number(i.highDelay);
      if (!Number.isSafeInteger(expiryRaw) || !Number.isSafeInteger(mediumRaw) || !Number.isSafeInteger(highRaw)) {
        fail('InvalidSessionParams');
      }
      const expiry = expiryRaw;
      const mediumDelay = mediumRaw;
      const highDelay = highRaw;

      if (maxPerTx <= 0n || capTotal < maxPerTx) fail('InvalidSessionParams');
      if (expiry <= this.now) fail('InvalidSessionParams');
      if (mediumDelay < 0 || highDelay < 0) fail('InvalidSessionParams');
      if (mediumDelay > MAX_DELAY || highDelay > MAX_DELAY || highDelay < mediumDelay) {
        fail('InvalidSessionParams');
      }
      if (operator === payer) fail('InvalidSessionParams');
      if (guardian === payer || (guardian !== ZERO && guardian === operator)) {
        fail('InvalidSessionParams');
      }

      const sessionId = this.nextSessionId++;
      this.sessions.set(sessionId, {
        payer, operator, guardian, maxPerTx, capTotal,
        spent: 0n, expiry, mediumDelay, highDelay,
        paused: false, revoked: false
      });
      this._log('SessionUpdated', {
        sessionId, payer, operator, guardian,
        maxPerTx: maxPerTx.toString(), capTotal: capTotal.toString(),
        expiry, paused: false
      });
      return sessionId;
    }

    setSessionPaused(caller, sessionId, paused) {
      const s = this._session(sessionId);
      if (addr(caller) !== s.payer) fail('NotSessionPayer');
      if (s.revoked) fail('SessionRevokedErr');
      s.paused = !!paused;
      this._log('SessionUpdated', {
        sessionId: Number(sessionId), payer: s.payer, operator: s.operator,
        guardian: s.guardian, maxPerTx: s.maxPerTx.toString(),
        capTotal: s.capTotal.toString(), expiry: s.expiry, paused: s.paused
      });
    }

    revokeSession(caller, sessionId) {
      const s = this._session(sessionId);
      if (addr(caller) !== s.payer) fail('NotSessionPayer');
      if (s.revoked) fail('SessionRevokedErr');
      s.revoked = true;
      this._log('SessionRevoked', { sessionId: Number(sessionId), payer: s.payer });
    }

    computeCommitment(args) {
      return C.computeCommitment({
        chainId: this.chainId,
        contractAddress: this.contractAddress,
        sessionId: args.sessionId,
        payer: args.payer,
        recipient: args.recipient,
        amountRaw: args.amountRaw,
        riskScore: args.riskScore,
        attestationHash: args.attestationHash,
        deadline: args.deadline
      });
    }

    /*
     * input: { recipient, amount, riskScore, attestationHash,
     *          commitmentHash, deadline }
     * Funds move payer -> contract inside the token ledger.
     */
    createEscrow(caller, sessionId, input) {
      const s = this._session(sessionId);
      const i = input || {};
      if (s.revoked) fail('SessionRevokedErr');
      if (s.paused) fail('SessionPausedErr');
      if (this.now >= s.expiry) fail('SessionExpiredErr');
      const from = addr(caller);
      if (from !== s.payer && from !== s.operator) fail('NotSessionActor');
      const recipient = addr(i.recipient);
      if (recipient === ZERO || recipient === s.payer || recipient === this.contractAddress) {
        fail('InvalidRecipient');
      }
      const amount = BigInt(i.amount);
      if (amount <= 0n) fail('InvalidAmount');
      if (amount > s.maxPerTx) fail('PerTxCapExceeded');
      if (amount > s.capTotal - s.spent) fail('CumulativeCapExceeded');
      const riskScore = Number(i.riskScore);
      if (!Number.isInteger(riskScore) || riskScore < 0 || riskScore > 100) fail('InvalidScore');
      const attestationHash = String(i.attestationHash || '').toLowerCase();
      const commitmentHash = String(i.commitmentHash || '').toLowerCase();
      if (!/^0x[0-9a-f]{64}$/.test(attestationHash) || attestationHash === '0x' + '0'.repeat(64)) {
        fail('InvalidHash');
      }
      if (!/^0x[0-9a-f]{64}$/.test(commitmentHash) || commitmentHash === '0x' + '0'.repeat(64)) {
        fail('InvalidHash');
      }
      const deadlineRaw = Number(i.deadline);
      if (!Number.isSafeInteger(deadlineRaw)) fail('InvalidDeadline');
      const deadline = deadlineRaw;
      if (deadline <= this.now) fail('InvalidDeadline');
      const expected = this.computeCommitment({
        sessionId: Number(sessionId), payer: s.payer, recipient,
        amountRaw: amount, riskScore, attestationHash, deadline
      });
      if (commitmentHash !== expected) fail('CommitmentMismatch');

      const tier = tierOf(riskScore);
      let releaseNotBefore;
      if (tier === 0) releaseNotBefore = this.now;
      else if (tier === 1) releaseNotBefore = this.now + s.mediumDelay;
      else if (tier === 2) {
        if (s.guardian === ZERO) fail('HighTierNeedsGuardian');
        releaseNotBefore = this.now + s.highDelay;
      } else {
        releaseNotBefore = Number.MAX_SAFE_INTEGER; // quarantined marker
      }
      if (tier !== 3 && deadline <= releaseNotBefore) fail('DeadlineBeforeUnlock');

      // token ledger pull with allowance and balance checks
      if (this.allowance(s.payer, this.contractAddress) < amount) fail('InsufficientAllowance');
      if (this.balanceOf(s.payer) < amount) fail('InsufficientBalance');

      const escrowId = this.nextEscrowId++;
      s.spent += amount;
      this.escrows.set(escrowId, {
        sessionId: Number(sessionId), payer: s.payer, recipient,
        amount, riskScore, tier, status: 1, guardianApproved: false,
        attestationHash, commitmentHash,
        createdAt: this.now, deadline, releaseNotBefore
      });
      this._log('EscrowCreated', {
        escrowId, sessionId: Number(sessionId), payer: s.payer, recipient,
        amount: amount.toString(), riskScore, tier,
        releaseNotBefore, deadline, attestationHash, commitmentHash
      });

      this._move(s.payer, this.contractAddress, amount);
      const inner = this.allowances.get(s.payer);
      inner.set(this.contractAddress, inner.get(this.contractAddress) - amount);
      return escrowId;
    }

    guardianApprove(caller, escrowId) {
      const e = this._escrow(escrowId);
      if (e.status !== 1) fail('EscrowNotFunded');
      if (e.tier !== 2) fail('EscrowNotHighTier');
      const s = this.sessions.get(e.sessionId);
      if (addr(caller) !== s.guardian) fail('NotGuardian');
      e.guardianApproved = true;
      this._log('GuardianApproved', { escrowId: Number(escrowId), guardian: s.guardian });
    }

    release(caller, escrowId) {
      const e = this._escrow(escrowId);
      if (e.status !== 1) fail('EscrowNotFunded');
      if (e.tier === 3) fail('Quarantined');
      const s = this.sessions.get(e.sessionId);
      if (s.revoked) fail('SessionRevokedErr');
      if (s.paused) fail('SessionPausedErr');
      if (this.now >= s.expiry) fail('SessionExpiredErr');
      if (this.now > e.deadline) fail('DeadlinePassed');
      if (this.now < e.releaseNotBefore) fail('TimelockActive', e.releaseNotBefore);
      if (e.tier === 2 && !e.guardianApproved) fail('GuardianApprovalMissing');

      e.status = 2;
      this._log('EscrowReleased', {
        escrowId: Number(escrowId), recipient: e.recipient, amount: e.amount.toString()
      });
      this._move(this.contractAddress, e.recipient, e.amount);
      return true;
    }

    revokeEscrow(caller, escrowId) {
      const e = this._escrow(escrowId);
      if (e.status !== 1) fail('EscrowNotFunded');
      if (addr(caller) !== e.payer) fail('NotPayer');
      e.status = 3;
      this._log('EscrowRevoked', {
        escrowId: Number(escrowId), payer: e.payer, amount: e.amount.toString()
      });
      this._move(this.contractAddress, e.payer, e.amount);
      return true;
    }

    revokeEscrows(caller, escrowIds) {
      const ids = Array.from(escrowIds || [], (x) => Number(x));
      if (!ids.length || ids.length > 64) fail('InvalidBatchSize');
      if (new Set(ids).size !== ids.length) fail('DuplicateEscrowId');
      const actor = addr(caller);
      const rows = ids.map((id) => this._escrow(id));
      rows.forEach((e) => {
        if (e.status !== 1) fail('EscrowNotFunded');
        if (actor !== e.payer) fail('NotPayer');
      });
      let total = 0n;
      rows.forEach((e, i) => {
        e.status = 3;
        total += e.amount;
        this._log('EscrowRevoked', {
          escrowId: ids[i], payer: e.payer, amount: e.amount.toString()
        });
      });
      this._log('EscrowsBatchRevoked', {
        payer: actor, count: ids.length, totalAmount: total.toString()
      });
      this._move(this.contractAddress, actor, total);
      return true;
    }

    releaseBlocker(escrowId) {
      const e = this.escrows.get(Number(escrowId));
      if (!e) fail('EscrowUnknown');
      if (e.status !== 1) return 'not_funded';
      if (e.tier === 3) return 'quarantined';
      const s = this.sessions.get(e.sessionId);
      if (s.revoked) return 'session_revoked';
      if (s.paused) return 'session_paused';
      if (this.now >= s.expiry) return 'session_expired';
      if (this.now > e.deadline) return 'deadline_passed';
      if (this.now < e.releaseNotBefore) return 'timelock';
      if (e.tier === 2 && !e.guardianApproved) return 'guardian';
      return '';
    }

    _move(from, to, amount) {
      const f = addr(from);
      const t = addr(to);
      const bal = this.balances.get(f) || 0n;
      if (bal < amount) fail('InsufficientBalance');
      this.balances.set(f, bal - amount);
      this.balances.set(t, (this.balances.get(t) || 0n) + amount);
      this._log('Transfer', { from: f, to: t, amount: amount.toString() });
    }

    exportAudit() {
      return JSON.stringify({
        chainId: this.chainId.toString(),
        contractAddress: this.contractAddress,
        exportedAt: this.now,
        sessions: [...this.sessions.entries()].map(([id, s]) => Object.assign({ sessionId: id }, s, {
          maxPerTx: s.maxPerTx.toString(), capTotal: s.capTotal.toString(), spent: s.spent.toString()
        })),
        escrows: [...this.escrows.entries()].map(([id, e]) => Object.assign({ escrowId: id }, e, {
          amount: e.amount.toString(),
          status: ['none', 'funded', 'released', 'revoked'][e.status],
          tierName: ['low', 'medium', 'high', 'critical'][e.tier]
        })),
        audit: this.audit
      }, null, 2);
    }
  }

  return { PayGuardSim, SimError, tierOf, ZERO, MAX_DELAY };
}));
