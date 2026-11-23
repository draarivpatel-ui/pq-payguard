# PQ PayGuard architecture

Deep reference for the pieces the README summarizes: the escrow contract,
the off-chain commitment layer, the browser simulator, and the post-quantum
workbench. Everything on this page maps to a file or a test in the repo.

## System layers

```
+---------------------------+  +----------------------------+  +---------------+
|   scoring + commitment    |  |   on-chain enforcement     |  |  verification |
|   (src/, zero deps, JS)   |  |   (contracts/, Solidity)   |  |  (test/, sim) |
+---------------------------+  +----------------------------+  +---------------+
  risk.js   exposure score      PQPayGuardEscrow.sol            sim.js mirror
  commit.js attestation +       MockTUSD8.sol (6 decimals)      forge unit/fuzz/
  chain.js  Aevum constants +   mocks/ReentrantToken.sol          invariant tests
            calldata                                            anvil parity vs
  abi.js    ABI codec                                           real EVM bytecode
  keccak.js keccak-256                                          browser-check.mjs
```

The boundary is deliberate: all post-quantum analysis happens off chain in
auditable JavaScript, and the Solidity contract consumes exactly one input,
the score, bound by a commitment. The contract contains no cryptography
beyond `keccak256` and an ERC-20 interface.

## Contract state machine

`PQPayGuardEscrow.sol` (Solidity 0.8.30, cancun, `via_ir`, optimizer 200).

**Session** - a payer-scoped policy envelope:

| Field | Meaning |
| --- | --- |
| `payer` | Session owner; the only address that may pause or revoke |
| `operator` | Optional agent key allowed to create escrows |
| `guardian` | Optional co-signer, required for the High tier |
| `maxPerTx` | Per-escrow spend cap in raw tUSD8 units |
| `capTotal` / `spent` | Cumulative cap and the running total escrowed |
| `expiry` | Unix time after which the session is inactive |
| `mediumDelay` / `highDelay` | Timelocks applied to those tiers |
| `paused` / `revoked` | Payer controlled freeze and irreversible kill switch |

**Escrow** - one payment instance bound to a score:

| Field | Meaning |
| --- | --- |
| `sessionId` | Policy the escrow was created under |
| `payer` / `recipient` | Refund source and release destination |
| `amount` | Raw 6-decimal tUSD8 units, never floats |
| `riskScore` / `tier` | 0-100 mapped to low/medium/high/critical |
| `status` | none/funded/released/revoked |
| `guardianApproved` | High-tier co-sign flag |
| `attestationHash` | SHA-256 of the canonical score report |
| `commitmentHash` | keccak over all bound fields, recomputed on chain |
| `createdAt` / `deadline` | Funding time and last allowed release time |
| `releaseNotBefore` | First timestamp at which release is allowed |

**Tier gate** - `release(id)` outcome by tier:

- Low (0-29): releases to the recipient once funded.
- Medium (30-59): releases after `mediumDelay` from funding; payer may
  `revokeEscrow` inside the window.
- High (60-84): releases after `highDelay` and a `guardianApprove` call.
- Critical (85-100): `release()` always reverts; the payer reclaims via
  `revokeEscrow`.

## Commitment scheme

```
attestationHash = SHA256("PQPG-ATTEST" || canonical(score report))
commitmentHash  = keccak256(abi.encode(
    block.chainid, address(this), sessionId,
    payer, recipient, amount, score, attestationHash, deadline))
```

`createEscrow` recomputes `commitmentHash` on chain from the supplied fields
and reverts unless it equals the submitted value. Consequences:

- A caller cannot lower the score without breaking the binding.
- Replays across chains fail because `chainid` is inside the preimage.
- Replays across deployments fail because `address(this)` is bound.
- The evidence behind the score cannot be swapped because
  `attestationHash` is bound too.

The off-chain twin lives in `commit.js`; `test/parity.test.js` and the anvil
suite prove the JS preimage matches the contract's encoding byte for byte
against a real EVM.

## ABI surface

```
createSession(address operator, address guardian,
              uint256 maxPerTx, uint256 capTotal, uint64 expiry,
              uint64 mediumDelay, uint64 highDelay)
setSessionPaused(uint256 sessionId, bool paused)
revokeSession(uint256 sessionId)
createEscrow(uint256 sessionId, address recipient, uint256 amount,
             uint8 riskScore, bytes32 attestationHash,
             bytes32 commitmentHash, uint64 deadline)
guardianApprove(uint256 escrowId)
release(uint256 escrowId)
revokeEscrow(uint256 escrowId)
```

Views: `getSession`, `getEscrow`, `releaseBlocker`, `computeCommitment`,
`tierOf`, `nextSessionId`, `nextEscrowId`, `token`, tier bound constants,
`MAX_DELAY`. Events: `SessionUpdated`, `SessionRevoked`, `EscrowCreated`,
`GuardianApproved`, `EscrowReleased`, `EscrowRevoked` - the whole lifecycle
is auditable on the explorer.

## API examples (off-chain layer)

```js
const CH = require('./src/chain.js');
const R = require('./src/risk.js');
const C = require('./src/commit.js');

// score a route
const s = R.exposureScore({ scheme: 'rsa-2048', keyRevealed: true,
  valueTusd: 1500, ageDays: 400 });
// -> { score, tier, tierName, scheme, factors:[{label, points}] }

// exact 6-decimal units, no floats
const amountRaw = CH.parseTokenUnits('250.5');        // -> 250500000n

// encode a call for the wallet or a script
const data = CH.buildCreateEscrow({
  sessionId: 0, recipient: '0x...', amountRaw, riskScore: s.score,
  attestationHash: '0x...', commitmentHash: '0x...', deadline: 1735000000
});

// explorer links
CH.explorerTxUrl(txHash); CH.explorerAddressUrl(contract);
```

`sim.js` (`PayGuardSim`) exposes the same method names as the contract and
throws `SimError` with the exact Solidity revert names, so the browser demo
and `test/` exercise the same branches the EVM does.

## Verification chain

| Layer | What it proves | Where |
| --- | --- | --- |
| forge unit tests | every method's happy path and revert names | `test/PQPayGuardEscrow.t.sol` |
| forge fuzz | tier mapping, caps, timelocks, commitment sensitivity (256 runs) | `test/PQPayGuardEscrowExtended.t.sol` |
| forge invariants | escrow solvency and release gating (64 runs x depth 16) | `test/PQPayGuardEscrowInvariant.t.sol` |
| JS suites | risk, abi, keccak, commitment, sim, rpc, signing, attacks, receipts, UI wiring | `test/*.test.js` |
| anvil parity | JS calldata + commitment against real EVM bytecode | `test/anvil.test.js` |
| compliance | dashes, vendor names, secrets, scope disclosures | `test/compliance.test.js` |
| browser audit | headless render, all six attacks, overflow, bookmarks | `scripts/browser-check.mjs` |
| preflight | env, key format, toolchain, live chain id, block, token | `scripts/qday-preflight.mjs` |

## Known constraints

- Testnet only: `tUSD8`/`tQDAY` carry no value and none is promised.
- The score is an educational heuristic, not a certified cryptanalysis.
- The contract does no post-quantum signature verification; it enforces the
  consequence of an off-chain score.
- `release()` is permissionless by design.
- The ERC-8004 identity registry is not assumed to exist on Aevum; the
  scoped session operator key plays the agent-credential role, and that
  substitution is stated rather than hidden.
- The frontend is a static page; no backend, no Dockerfile, no runtime
  dependencies.

## Roadmap

1. Deploy + verify on Aevum testnet (runbook in `DEMO.md`).
2. Wire the UI's live-write path to the deployed address.
3. Adopt the ERC-8004 registry for agent identity if/when it ships on
   Aevum; the session operator abstraction already fits its shape.
4. Follow QDay's post-quantum migration: move the attestation signature to
   a PQ scheme supported by the network at mainnet.
5. Package the escrow + session pattern as a reusable template for other
   builders (the modules under `src/` are already standalone MIT pieces).
