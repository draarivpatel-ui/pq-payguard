# PQ PayGuard demo guide

This file is the judge-facing walkthrough of the live demo and the exact
runbook for the Aevum testnet deployment. Nothing here is simulated prose:
every UI step describes a control that exists on the page today, and every
command is the one the repo actually ships.

Live demo: <https://aariv.me/pq-payguard/>
Public repo: <https://github.com/draarivpatel-ui/pq-payguard>

## Deployment status

**Ready for 1-command deploy with the funded testnet wallet.** The contract is
written, compiled and covered by 110 passing Foundry tests, and the deploy +
verify path is scripted end to end. As of the last update of this file, no
testnet deployment has been performed yet, so no transaction hashes are
claimed below. The `Deployment record` table is a template that is filled in
from the real `deployments/qday-testnet.json` the deploy script writes.

## Exact architecture

```
 browser / node (zero runtime dependencies, works offline)
 +------------------------------------------------------------------+
 |  risk.js     exposure score 0..100 with itemized factors          |
 |  commit.js   SHA-256 attestation + keccak commitment preimage     |
 |  chain.js    Aevum chain 44005 constants + calldata builders      |
 |  abi.js      hand rolled ABI codec (keccak.js selectors)          |
 |  sim.js      PayGuardSim: branch-exact mirror of the contract     |
 |  rpc.js      opt-in JSON-RPC reads + deterministic fallback       |
 |  wallet.js   EIP-1193 connect + switch to 0xabe5                  |
 |  pqsig.js / attacks.js / compare.js / receipt.js / selftest.js    |
 +-----------------------------+------------------------------------+
                               | calldata / signed tx
                               v
 +------------------------------------------------------------------+
 |  PQPayGuardEscrow.sol  (Solidity 0.8.30, cancun, via_ir)          |
 |                                                                  |
 |  Session {operator, guardian, maxPerTx, capTotal, expiry,         |
 |           mediumDelay, highDelay, spent, paused, revoked}         |
 |  Escrow  {sessionId, payer, recipient, amount, score, tier,       |
 |           attestationHash, commitmentHash, deadline, status,      |
 |           guardianOk}                                             |
 |                                                                  |
 |  createSession / setSessionPaused / revokeSession                 |
 |  createEscrow    recompute commitment, pull tUSD8                 |
 |  release         tier gate: instant | timelock | +guardian | never|
 |  guardianApprove / revokeEscrow                                   |
 +------------------------------------------------------------------+
                               |
                               v
             tUSD8 (ERC-20, 6 decimals)
    0x456569838f1d43009A91ebA4263147Afd7233483
```

One end to end flow, as the challenge requires:

1. The payer opens a session: an operator agent key, a guardian, a
   per-escrow cap, a cumulative cap, an expiry, and the Medium/High delays.
2. Off chain, `risk.js` scores the receiving scheme 0..100 and `commit.js`
   builds the domain separated `attestationHash` plus the keccak
   `commitmentHash` over chain id, contract, session, payer, recipient,
   amount, score, attestation and deadline.
3. `createEscrow` recomputes the commitment on chain. A mismatched field
   (including a lowered score) reverts before any token moves.
4. The tier picks the release path: Low 0-29 instant, Medium 30-59 session
   timelock, High 60-84 extended timelock plus guardian co-sign, Critical
   85-100 quarantined with `release()` always reverting.
5. The payer's `revokeEscrow` is the escape hatch that refunds any funded
   escrow in any tier, and `revokeSession` freezes every escrow under it.

## Threat model

| # | Threat | Contract / system mitigation |
| --- | --- | --- |
| 1 | Caller submits a lower risk score than the attestation carried | `createEscrow` recomputes the keccak commitment over all nine bound fields and reverts on mismatch |
| 2 | Compromised operator or agent key goes on a spending run | Session enforces per-transaction cap, cumulative cap and expiry; payer revokes the session instantly |
| 3 | Tampered transfer calldata or swapped recipient | Commitment binds payer, recipient, amount and deadline; the UI never relays unsigned calldata |
| 4 | Replay of a stale attestation or old escrow | `deadline` is inside the commitment; session `expiry` plus the per-escrow deadline bound acceptance |
| 5 | Merchant tries to look safer by downgrading its scheme | Score and scheme evidence hash are bound at creation; a different score produces a different commitment |
| 6 | Guardian overreach or refusal griefs a Low/Medium payment | Guardian co-sign is only mandatory on the High tier; the payer can always `revokeEscrow` and reclaim |
| 7 | Reentrancy through the token callback | Checks-effects-interactions, a reentrancy lock, exact balance deltas; proven with a hostile `ReentrantToken` mock |
| 8 | `release()` frontrunning or permissioned release | Release is permissionless by design: the outcome depends only on the stored tier, timelock and guardian flag |

## Live web demo walkthrough

The page at `https://aariv.me/pq-payguard/` runs entirely client side. It
reaches the network only when you press `Probe testnet` or `Read on chain`, or
use the wallet buttons. The walkthrough below touches every judging surface in order.

1. **Hero and the gate.** The landing panel shows the four-tier table. Point
   at the Critical row: quarantined, `release()` always reverts. This table
   is the contract, not marketing copy: the same boundaries live in
   `tierOf` in Solidity and in `sim.js`.
2. **Score a payment** (`#score`). Leave the defaults, including the already
   checked `public key already revealed on chain` box, then change
   `Receiving signature scheme` to `rsa-2048`. The ring lands on `100`
   (clamped) at `critical`. Untick the reveal box and switch to `ml-dsa-65`:
   the same payment drops to `low`.
   Under it, `attestationHash`, `commitmentHash` and the exact
   `createEscrow` calldata recompute live. Change any escrow field and the
   commitment changes, which is the binding property the contract enforces.
3. **Run the state machine** (`#sim`). Press `Create session`, then `Fund
   escrow`. With a low score the escrow releases instantly. Fund a second
   escrow with `Risk score override` set to `70`, act as the guardian to
   `guardianApprove`, then `Warp` past the high delay and release it. Fund
   a third at score `95`: `release` reverts, and the payer `revoke` returns
   the tokens. Every step lands in the audit trail, exportable as JSON.
4. **Break it** (`#attacks`). `Run all six attacks`: signature replay,
   cross-chain domain forgery, one-time leaf reuse, Merkle proof tampering,
   a toy Shor drain against an exposed classical key, and a limit/guardian
   bypass. Every verdict is computed live against the same `PayGuardSim`
   the anvil suite checks against real EVM bytecode.
5. **Cost and budget** (`#compare`). The comparator prices signature bytes
   and modeled gas across Merkle heights; the planner shows how fast a
   stateful hash wallet burns leaves and when rotation is mandatory.
6. **Receipts and self tests** (`#verify`). `Build + WOTS sign` a receipt,
   verify it, then `Verify tampered copy` to watch detection. `Run self
   tests` executes the 35-check in-page battery (SHA-256 and keccak known
   answers, WOTS round trips, Merkle proofs, all six attacks, receipts,
   bookmarks, simulator).
7. **Testnet panel** (`#network`). `Probe testnet` reads the live chain id
   `44005` (`0xabe5`) and block number over `https://rpc-test.qday.info`.
   `Connect wallet` + `Switch to Aevum` exercise the EIP-1193 path.
   `Read on chain` queries a deployed escrow once an address exists.

## Two-minute demo video shot list

For the submission-form demo video. Record at 1920x1080, testnet wallet
funded beforehand, hashes kept in a text file for instant pasting.

| Time | Shot | Narration beat |
| --- | --- | --- |
| 0:00 - 0:15 | Hero gate table, zoom on Critical row | Risk scores are usually metadata. This one changes what the contract does. |
| 0:15 - 0:40 | `#score`: rsa-2048 + revealed goes critical, ml-dsa-65 goes low; show hashes recompute | Same payment, different release path, bound before funds move. |
| 0:40 - 1:10 | `#sim`: create session, fund low escrow, instant release; fund critical, release reverts, payer reclaims | The gate is enforced on chain, shown here branch for branch. |
| 1:10 - 1:30 | `#attacks`: run all six, pan the verdicts | Replay, forgery, leaf reuse, tampering, drain and bypass, all blocked. |
| 1:30 - 1:45 | `#verify`: run self tests, show the green table | 35 in-page checks; 407 repo tests total (297 JS + 110 Foundry). |
| 1:45 - 2:00 | `#network`: probe testnet, show chain id + explorer link | Live on QDay Aevum chain 44005, test tokens only. |

Backup plan if live RPC is slow during the live finalist call: this
recorded video plus the simulator, which is a branch-exact offline mirror.

## Testnet deploy runbook (1 command after funding)

Prerequisites: Foundry (`forge`, `cast`), Node 18+, a dedicated
**testnet-only** key (never a real-funds key), and `tQDAY` gas from the
official faucet.

```bash
# 1. fund the deployer address at https://faucet.qday.info/en

# 2. configure the key (file is gitignored, placeholders only)
cp .env.example .env       # then paste the testnet-only key

# 3. preflight: env, key, toolchain, live chain id, block, tUSD8, balance
node scripts/qday-preflight.mjs

# 4. deploy (builds, deploys, verifies token() view, writes the record)
node scripts/deploy-qday.mjs

# 5. verify contract source on the Blockscout explorer
#    (the constructor arg is the tUSD8 address ABI encoded, cast computes it)
forge verify-contract <DEPLOYED_ADDRESS> \
  contracts/PQPayGuardEscrow.sol:PQPayGuardEscrow \
  --chain-id 44005 \
  --verifier blockscout \
  --verifier-url https://explorer-test.qday.info/api/ \
  --constructor-args $(cast abi-encode "constructor(address)" 0x456569838f1d43009A91ebA4263147Afd7233483)
```

`deploy-qday.mjs` checks the chain id, the deployer gas balance and the
`token()` view after deployment, then writes `deployments/qday-testnet.json`
with the address, deploy tx and explorer links.

## Deployment record

Filled in only from the real `deployments/qday-testnet.json` after the
deploy runs. PENDING means not done yet, never guessed.

| Item | Value |
| --- | --- |
| Contract address | PENDING testnet deploy |
| Deploy tx hash | PENDING testnet deploy |
| Explorer (address) | PENDING testnet deploy |
| Explorer (tx) | PENDING testnet deploy |
| Source verified | PENDING `forge verify-contract` run |
| Session create tx | PENDING |
| Low-tier escrow + release tx | PENDING |
| Critical-tier escrow + revert + revoke tx | PENDING |

## Expected on-chain trail after deploy

| Step | Method | Event to show on the explorer |
| --- | --- | --- |
| Open policy | `createSession` | `SessionUpdated` |
| Fund low-risk escrow | `createEscrow` | `EscrowCreated` with tier `low` |
| Pay out | `release` | `EscrowReleased` |
| Fund critical escrow | `createEscrow` | `EscrowCreated` with tier `critical` |
| Quarantine proof | `release` reverts | revert visible in tx status |
| Payer reclaim | `revokeEscrow` | `EscrowRevoked` + refund |

## Honest scope

- Testnet only. `tUSD8` and `tQDAY` have no monetary value; no tokens are
  issued or promised.
- The exposure score is a transparent, documented heuristic. It is not a
  certified cryptanalysis or a security guarantee.
- The contract does not perform post-quantum signatures. QDay is EVM
  compatible today with a post-quantum migration path; the PQ analysis
  lives off chain and the contract enforces its consequence.
- The toy elliptic curve in the Shor demo is a DLP illustration, labeled as
  such in page.


## Batch rescue beat

In the simulator, fund several escrows as the payer, then use **Batch rescue funded**. The audit trail shows one `EscrowRevoked` event per escrow plus one aggregate `EscrowsBatchRevoked`, mirroring the contract emergency path.
