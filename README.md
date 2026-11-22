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

Deployed contract: pending testnet deployment (see `deployments/` once live).

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
7. **Documentation.** This file, the risk-gate table, security model, exact
   reproduction commands, and the deploy/verify runbook.
8. **Originality.** Risk scores as passive metadata are common; a score that is
   cryptographically bound to an escrow release path is the differentiator.

## Quick start

Prerequisites: Node 18+, Foundry (`forge`, `anvil`, `cast`).

```bash
# contracts: unit + fuzz + invariant suites (42 tests)
forge test

# javascript: risk, abi, keccak, commitment, simulator, rpc, signing,
# anvil parity against a real EVM, and compliance scans
npm test

# compile and print artifact facts
node scripts/compile.mjs

# open the demo (zero dependency static page, works offline)
open index.html
```

### Deploy to Aevum testnet

```bash
cp .env.example .env        # fill in a dedicated TESTNET-ONLY key
export QDAY_PRIVATE_KEY=... # or source .env
node scripts/deploy-qday.mjs
```

The deploy script verifies chain id, gas balance, and the `token()` view after
deployment, then writes `deployments/qday-testnet.json`. Fund the deployer
from `https://faucet.qday.info/en` first.

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
src/ui.js + index.html + styles.css   zero-dependency demo app
scripts/lib/eth.mjs              secp256k1, RLP, EIP-155 signing, JSON-RPC
scripts/compile.mjs              forge build + artifact facts
scripts/deploy-qday.mjs          testnet deployment + verification
test/*.t.sol                     forge unit, fuzz, invariant, reentrancy tests
test/*.test.js                   node:test suites incl. anvil parity + compliance
```

## License

MIT. See `LICENSE`.
