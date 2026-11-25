# PQ PayGuard

Quantum exposure scoring made binding on payments. PQ PayGuard is a risk-gated
`tUSD8` escrow for the QDay Aevum testnet: the same payment takes a different
on-chain path depending on the computed quantum exposure of the receiving
cryptographic scheme, and every step of that decision is verifiable both on
chain and off chain.

Built for the DoraHacks QDay Aevum Builder Challenge. Testnet only. No tokens
are issued or promised.

## The problem it solves

Post-quantum migration dashboards score wallets and contracts, but the score
is usually stored as passive metadata: nothing on chain actually behaves
differently because of it. PQ PayGuard closes that gap. A computed exposure
score is bound into a payment commitment, and the escrow contract maps the
score to one of four release paths with different security postures:

| Score    | Tier     | Contract behavior                                        |
| -------- | -------- | -------------------------------------------------------- |
| 0 - 29   | Low      | Immediate release once the commitment verifies            |
| 30 - 59  | Medium   | Session-configured timelock; payer can revoke in the window |
| 60 - 84  | High     | Extended timelock plus mandatory guardian co-sign          |
| 85 - 100 | Critical | Quarantined. `release()` always reverts; payer reclaims    |

The score is not decoration. `createEscrow` recomputes the commitment over
`chainid`, the contract address, the session, payer, recipient, amount, score,
attestation hash and deadline, and reverts on any mismatch: a caller cannot
quietly submit a lower score than the one the attestation was built for.

## Architecture

```
            off chain (browser / node, zero runtime deps)
  +------------------------------------------------------------------+
  |  risk.js     exposure score 0..100 + factor list                  |
  |  commit.js   SHA-256 attestation + keccak commitment preimage     |
  |  chain.js    Aevum constants + calldata builders                  |
  |  abi.js      hand-rolled ABI encoder/decoder (selectors via       |
  |              keccak.js, no external crypto)                       |
  |  sim.js      state machine mirror of the contract                 |
  |  rpc.js      opt-in JSON-RPC reads + deterministic fallback       |
  |  wallet.js   EIP-1193 connect + chain switch to 0xabe5            |
  +------------------------------+-----------------------------------+
                                 | calldata / signed tx
                                 v
  +------------------------------------------------------------------+
  |              PQPayGuardEscrow (Solidity, chain 44005)             |
  |                                                                  |
  |   payer creates Session {operator, guardian, maxPerTx, capTotal,  |
  |   expiry, mediumDelay, highDelay, paused, revoked}                |
  |                                                                  |
  |   createEscrow(sessionId, recipient, amount, riskScore,           |
  |     attestationHash, commitmentHash, deadline)                    |
  |      -> tierOf(score) picks the release path                      |
  |      -> pulls amount of tUSD8 from the payer                      |
  |                                                                  |
  |   release(id)          gated by tier + timelock + guardian        |
  |   guardianApprove(id)  guardian only, High tier only              |
  |   revokeEscrow(id)     payer escape hatch, refunds, any tier      |
  |   setSessionPaused / revokeSession   instant freeze / kill switch |
  +------------------------------------------------------------------+
                                 |
                                 v
                     tUSD8 (ERC-20, 6 decimals)
            0x456569838f1d43009A91ebA4263147Afd7233483
```

## Official QDay Aevum parameters

| Parameter        | Value                                        |
| ---------------- | -------------------------------------------- |
| Chain name       | QDay Aevum Testnet                           |
| Chain ID         | `44005` (`0xabe5`)                           |
| RPC              | `https://rpc-test.qday.info`                 |
| Explorer         | `https://explorer-test.qday.info`            |
| Faucet           | `https://faucet.qday.info/en`                |
| Gas token        | `tQDAY` (18 decimals)                        |
| tUSD8 token      | `0x456569838f1d43009A91ebA4263147Afd7233483` |
| tUSD8 decimals   | `6`                                          |
| Faucet contract  | `0xE5074CBbd046AFb491EB8692abD6cF7ECCC6dEE5` |

Deployed contract: pending testnet deployment. Ready for 1-command deploy
with a funded testnet wallet; see `deployments/` once live and the runbook
in `DEMO.md`.

## Judging criteria map

1. **Aevum integration.** Purpose-built for chain `44005`: official RPC,
   explorer and faucet are wired into the UI, wallet helper, and deploy script;
   the escrow settles in the official `tUSD8` test token.
2. **Working demo.** A live escrow state-machine simulator plus an opt-in RPC
   inspector and EIP-1193 wallet connect, all in a zero-dependency static page.
3. **Technical quality.** Audited-style Solidity (checks-effects-interactions,
   reentrancy guard, custom errors, strict validation), a hand-rolled
   Keccak-256, secp256k1 and RLP stack in JS, and byte-exact
   off-chain/on-chain commitment parity verified against a real EVM.
4. **Security.** Commitment binding stops score substitution; sessions enforce
   per-tx caps, cumulative caps, expiry, pause and revocation; Critical tier
   payments are quarantined at the contract level; reentrancy is tested with a
   malicious token.
5. **PQ relevance.** The risk model scores recipient key schemes (secp256k1,
   RSA, Falcon, ML-DSA, SLH-DSA, hash-only) plus exposure modifiers, and the
   score gates funds, which is the behavior PQ readiness actually requires.
6. **UX.** Dark/light responsive UI, simulator with audit-log export,
   explorer links, tier badges, and an honest testnet scope disclosure.
7. **Documentation.** This file plus `ARCHITECTURE.md` (module map, ABI
   surface, verification chain, roadmap) and `DEMO.md` (walkthrough, threat
   model, deploy runbook, deployment record).
8. **Originality.** Risk scores as passive metadata are common; a score that is
   cryptographically bound to an escrow release path is the differentiator.

## Quick start

Prerequisites: Node 18+, Foundry (`forge`, `anvil`, `cast`).

```bash
# contracts: unit + fuzz + invariant suites (110 tests)
forge test

# javascript: risk, abi, keccak, commitment, simulator, rpc, signing,
# hash-signature workbench, attack scenarios, receipts, parity vectors,
# anvil parity against a real EVM, deploy preflight, the decision
# pipeline view model, and compliance scans (297 tests)
npm test

# compile and print artifact facts
node scripts/compile.mjs

# preflight: env/key format, toolchain, live chain id, block, tUSD8 and
# deployer balance; prints the exact deploy + verify runbook
node scripts/qday-preflight.mjs

# headless Chromium audit at 1440x900, 820x1180 and 390x844: console/page errors,
# external requests, horizontal overflow, all six attacks, comparator,
# self tests, receipts and bookmarks (117 checks)
node scripts/browser-check.mjs

# open the demo (zero dependency static page, works offline)
open index.html
```

### Deploy to Aevum testnet

```bash
cp .env.example .env        # fill in a dedicated TESTNET-ONLY key
node scripts/qday-preflight.mjs   # checks env, key, toolchain, live chain
node scripts/deploy-qday.mjs
```

The deploy script verifies chain id, gas balance, and the `token()` view after
deployment, then writes `deployments/qday-testnet.json`. Fund the deployer
from `https://faucet.qday.info/en` first. The full deploy plus explorer
source-verification runbook is in `DEMO.md`.

## Hash-signature workbench

Alongside the escrow, the page ships a pure-JS post-quantum signature
workbench (`src/pqsig.js`) so judges can run the cryptographic arguments
the product is built on:

- **Lamport-256 and WOTS (w = 4/16/64/256)** one-time signatures over the
  in-repo Keccak, with detached verification (`wotsPkFromSig` recovers the
  public key from signature plus message, as real XMSS-style verification
  does).
- **Merkle trees and proofs** binding one-time public keys, plus a stateful
  `HashWallet` with a used-leaf bitmap: a consumed leaf cannot sign twice.
- **Six live attack scenarios** (`src/attacks.js`) that execute real crypto
  against `PayGuardSim`, the contract-semantic simulator: signature replay
  and cross-domain forgery (rejected by the chain/contract-bound
  commitment), one-time leaf reuse (blocked by the bitmap; repeated reuse
  leaks both preimages per bit position, shown honestly), Merkle sibling
  tampering (rejected), a toy Shor ECDLP drain against an exposed classical
  public key versus commitment protection (compromised vs protected), and a
  limit/guardian bypass attempt (blocked by caps, timelocks and the
  guardian requirement).
- **Scheme comparator and key-budget planner** (`src/compare.js`): exact
  signature/public-key/proof bytes and modeled EVM gas across Merkle
  heights and WOTS parameters, next to classical and NIST PQC reference
  sizes, plus a remaining-leaf rotation warning.
- **Signed receipts and bookmarks** (`src/receipt.js`): SHA-256
  domain-separated receipts signed with a WOTS key, detached verification
  in page, CSV-injection-safe exports (JSON/CSV/Markdown), and a
  checksummed `#pq=` URL-fragment codec for scenario bookmarks.
- **In-page self-test battery** (`src/selftest.js`): 35 checks including
  FIPS 180-4 SHA-256 and Keccak known-answer vectors, sign/verify round
  trips, Merkle root reconstruction, leaf-exhaustion bounds, all six
  attacks, receipt tamper detection and the bookmark codec. `?selftest`
  runs it headlessly and exposes `window.__pqpgReport` for the audit
  script.

The toy elliptic curve (`y^2 = x^3 + 2x + 3 mod 97`) used in the Shor demo
is labeled in page as a DLP illustration, not a cryptanalytic claim.

## Decision pipeline

The first panel under the hero (`#pipeline`, `src/pipeline.js`) reads the
whole page as four stages and updates on every score change, simulator
action, attack run and receipt verification:

1. **Risk tier meter**: the score the next simulator escrow will commit (the
   score panel, or the escrow form override), its tier, the release path the
   contract assigns, and whether the receiving scheme is a PQ-resistant
   family or quantum-vulnerable under the score model (labeled as the score
   panel's scheme when the escrow form override supplies the score).
2. **Spend cap gate**: a preflight of `createEscrow`'s session, actor, per
   tx cap, cumulative cap, score, guardian, deadline, allowance and balance
   checks in the simulator's own branch order. `test/pipeline.test.js` proves the first
   failing check equals the real `PayGuardSim` revert over a grid of more
   than 1,400 scenarios; the simulator revert itself is shown after funding.
3. **Escrow state machine**: the latest escrow and the exact
   `releaseBlocker` the simulator reports (timelock, awaiting guardian, gate
   open, released, revoked, quarantined, frozen).
4. **WOTS receipt verifier**: the last receipt build or verify, its check
   count and the signing wallet's one time leaf map.

Each stage also lists the attacks from `src/attacks.js` that exercise it.
Nothing is pre-filled: before a session, escrow, attack run or receipt the
stage says so. The scheme chip is a label from the score model; the escrow
contract performs no post-quantum signatures.

## Security model

- **Commitment binding.** `keccak256(abi.encode(chainid, escrow, sessionId,
  payer, recipient, amount, score, attestationHash, deadline))` must equal the
  submitted `commitmentHash`. Changing any field (including the score) breaks
  the binding, and the contract recomputes it.
- **Attestation.** Off chain, the score report is canonicalized and hashed with
  SHA-256 into `attestationHash`, bound inside the commitment so the
  supporting evidence cannot be swapped either.
- **Session policy.** Per-tx cap, cumulative cap, expiry, pause and
  irreversible revocation, all enforced before funds move.
- **Escape hatch.** The payer can `revokeEscrow` any funded escrow (including
  quarantined Critical ones) and gets the tokens back.
- **Reentrancy.** All state-changing external calls are behind a guard, with
  effects before interactions, and a `ReentrantToken` mock proves the pull
  path cannot be reentered.
- **Integer money.** All amounts are raw 6-decimal integer units. `1.5 tUSD8`
  is `1500000` raw. The JS layer rejects more than six decimals.

## Scope and honesty

- Testnet only. No real funds, no value at risk, nothing issued or promised.
- The exposure score is a transparent heuristic for demonstration. It is
  **not** a security guarantee, an audit, or a formal risk assessment.
- The contract does not perform post-quantum signatures or PQC verification;
  PQ analysis happens off chain in the scoring module, and the contract
  enforces the *consequence* of the score.
- `release()` is permissionless by design: the gate alone decides the outcome.

## Environment variables

| Variable           | Required | Purpose                                    |
| ------------------ | -------- | ------------------------------------------ |
| `QDAY_PRIVATE_KEY` | deploy   | Testnet-only deployer key (64 hex chars)   |
| `QDAY_RPC_URL`     | optional | Override the default Aevum RPC endpoint    |
| `QDAY_TUSD8`       | optional | Override the tUSD8 token address           |
| `PQPG_FORGE_BIN`   | optional | forge binary name/path for tests           |
| `PQPG_ANVIL_BIN`   | optional | anvil binary name/path for tests           |

## Repository layout

```
contracts/PQPayGuardEscrow.sol   risk-gated escrow (the core deliverable)
contracts/MockTUSD8.sol          6-decimal test token for local EVM runs
contracts/mocks/ReentrantToken.sol  malicious token for reentrancy tests
src/keccak.js  abi.js  chain.js  risk.js  commit.js  sim.js  rpc.js  wallet.js
src/pqsig.js   Lamport/WOTS one-time signatures, Merkle proofs, HashWallet
src/attacks.js six live attack scenarios vs the contract-semantic simulator
src/compare.js scheme size/gas comparator + key-budget planner
src/receipt.js SHA-256 signed receipts, CSV-safe exports, bookmark codec
src/selftest.js 35-check in-page battery (?selftest exposes __pqpgReport)
src/pipeline.js four-stage decision pipeline view (pure derive + DOM binding)
src/ui.js + src/workbench.js + index.html + styles.css   zero-dep demo app
scripts/lib/eth.mjs              secp256k1, RLP, EIP-155 signing, JSON-RPC
scripts/compile.mjs              forge build + artifact facts
scripts/deploy-qday.mjs          testnet deployment + verification
scripts/qday-preflight.mjs       env/key/toolchain/live-RPC preflight check
scripts/browser-check.mjs        zero-dep CDP headless-Chromium audit
test/*.t.sol                     forge unit, fuzz, invariant, reentrancy tests
test/*.test.js                   node:test suites incl. anvil parity + compliance
```

## License

MIT. See `LICENSE`.
