// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-20 surface used by the escrow. tUSD8 on QDay Aevum
/// testnet (chain 44005) satisfies this interface.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title PQPayGuardEscrow
/// @notice Quantum-risk-gated tUSD8 escrow for the QDay Aevum testnet.
///
/// A computed quantum exposure score (0-100) is bound into each escrow through
/// a commitment hash that the contract verifies on chain. The stored score then
/// selects the release path:
///
///   tier        score      release behaviour
///   Low         0-29       immediate release to the recipient
///   Medium      30-59      session mediumDelay timelock, payer may revoke first
///   High        60-84      session highDelay timelock plus guardian co-sign
///   Critical    85-100     quarantined, never releases, payer reclaims
///
/// Sessions are scoped spend policies: a per escrow cap, a cumulative cap, an
/// expiry, optional operator (agent) and optional guardian, plus instant pause
/// and revocation. Revoking or pausing a session blocks new escrows and freezes
/// every pending release; escrowed funds remain reclaimable by the payer.
///
/// The contract holds no admin role. The only privileged actor on an escrow is
/// its payer; the only privileged actor on a session is its payer.
contract PQPayGuardEscrow {
    // ------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------

    enum Tier {
        Low,
        Medium,
        High,
        Critical
    }

    enum Status {
        None,
        Funded,
        Released,
        Revoked
    }

    /// @notice Scoped spend policy created by a payer.
    struct Session {
        address payer;
        address operator;    // optional agent that may create escrows
        address guardian;    // optional co-signer, required for High tier
        uint256 maxPerTx;    // max raw units per escrow
        uint256 capTotal;    // lifetime cumulative cap in raw units
        uint256 spent;       // raw units escrowed over the session lifetime
        uint64 expiry;       // unix time after which the session is inactive
        uint64 mediumDelay;  // release delay applied to Medium tier escrows
        uint64 highDelay;    // release delay applied to High tier escrows
        bool paused;         // payer controlled freeze
        bool revoked;        // irreversible kill switch
    }

    /// @notice One risk gated escrowed payment.
    struct Escrow {
        uint256 sessionId;
        address payer;
        address recipient;
        uint256 amount;
        uint8 riskScore;
        Tier tier;
        Status status;
        bool guardianApproved;
        bytes32 attestationHash;
        bytes32 commitmentHash;
        uint64 createdAt;
        uint64 deadline;           // last timestamp at which release is allowed
        uint64 releaseNotBefore;   // first timestamp at which release is allowed
    }

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    uint8 public constant SCORE_LOW_MAX = 29;
    uint8 public constant SCORE_MEDIUM_MAX = 59;
    uint8 public constant SCORE_HIGH_MAX = 84;
    uint8 public constant SCORE_CRITICAL_MAX = 100;
    uint64 public constant MAX_DELAY = 30 days;
    uint256 public constant MAX_BATCH_REVOKE = 64;

    /// @notice Official tUSD8 token on QDay Aevum testnet is the intended
    /// asset; the contract accepts any ERC-20 address at construction so the
    /// same code runs unchanged against MockTUSD8 in local EVM tests.
    IERC20 public immutable token;

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------

    uint256 public nextSessionId;
    uint256 public nextEscrowId;

    mapping(uint256 => Session) private _sessions;
    mapping(uint256 => Escrow) private _escrows;

    uint256 private _locked = 1;

    // ------------------------------------------------------------------
    // Events (audit trail)
    // ------------------------------------------------------------------

    event SessionUpdated(
        uint256 indexed sessionId,
        address indexed payer,
        address operator,
        address guardian,
        uint256 maxPerTx,
        uint256 capTotal,
        uint64 expiry,
        bool paused
    );
    event SessionRevoked(uint256 indexed sessionId, address indexed payer);
    event EscrowCreated(
        uint256 indexed escrowId,
        uint256 indexed sessionId,
        address indexed payer,
        address recipient,
        uint256 amount,
        uint8 riskScore,
        Tier tier,
        uint64 releaseNotBefore,
        uint64 deadline,
        bytes32 attestationHash,
        bytes32 commitmentHash
    );
    event GuardianApproved(uint256 indexed escrowId, address indexed guardian);
    event EscrowReleased(uint256 indexed escrowId, address indexed recipient, uint256 amount);
    event EscrowRevoked(uint256 indexed escrowId, address indexed payer, uint256 amount);
    event EscrowsBatchRevoked(address indexed payer, uint256 count, uint256 totalAmount);

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    error Reentrant();
    error TransferFailed();
    error TransferAmountMismatch();
    error ZeroAddress();
    error InvalidSessionParams();
    error InvalidRecipient();
    error InvalidAmount();
    error InvalidScore();
    error InvalidHash();
    error InvalidDeadline();
    error DeadlineBeforeUnlock();
    error SessionUnknown();
    error SessionRevokedErr();
    error SessionPausedErr();
    error SessionExpiredErr();
    error NotSessionPayer();
    error NotSessionActor();
    error PerTxCapExceeded();
    error CumulativeCapExceeded();
    error CommitmentMismatch();
    error HighTierNeedsGuardian();
    error EscrowUnknown();
    error EscrowNotFunded();
    error EscrowNotHighTier();
    error NotGuardian();
    error NotPayer();
    error Quarantined();
    error TimelockActive(uint64 releaseNotBefore);
    error GuardianApprovalMissing();
    error DeadlinePassed();
    error InvalidBatchSize();
    error DuplicateEscrowId();

    // ------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------

    modifier nonReentrant() {
        if (_locked == 2) revert Reentrant();
        _locked = 2;
        _;
        _locked = 1;
    }

    // ------------------------------------------------------------------

    constructor(address token_) {
        if (token_ == address(0)) revert ZeroAddress();
        token = IERC20(token_);
    }

    // ------------------------------------------------------------------
    // Session administration (payer only)
    // ------------------------------------------------------------------

    /// @notice Create a scoped spend policy.
    /// @param operator optional agent allowed to call createEscrow (0 for none)
    /// @param guardian optional co-signer for High tier escrows (0 for none)
    /// @param maxPerTx maximum raw token units for a single escrow
    /// @param capTotal lifetime cumulative cap in raw units
    /// @param expiry unix time after which the session stops working
    /// @param mediumDelay release delay applied to Medium tier escrows
    /// @param highDelay release delay applied to High tier escrows
    function createSession(
        address operator,
        address guardian,
        uint256 maxPerTx,
        uint256 capTotal,
        uint64 expiry,
        uint64 mediumDelay,
        uint64 highDelay
    ) external returns (uint256 sessionId) {
        if (maxPerTx == 0 || capTotal < maxPerTx) revert InvalidSessionParams();
        if (expiry <= block.timestamp) revert InvalidSessionParams();
        if (mediumDelay > MAX_DELAY || highDelay > MAX_DELAY || highDelay < mediumDelay) {
            revert InvalidSessionParams();
        }
        if (operator == msg.sender) revert InvalidSessionParams();
        if (guardian == msg.sender || (guardian != address(0) && guardian == operator)) {
            revert InvalidSessionParams();
        }

        sessionId = nextSessionId++;
        Session storage s = _sessions[sessionId];
        s.payer = msg.sender;
        s.operator = operator;
        s.guardian = guardian;
        s.maxPerTx = maxPerTx;
        s.capTotal = capTotal;
        s.expiry = expiry;
        s.mediumDelay = mediumDelay;
        s.highDelay = highDelay;

        emit SessionUpdated(sessionId, msg.sender, operator, guardian, maxPerTx, capTotal, expiry, false);
    }

    /// @notice Pause or unpause a session. A paused session cannot create
    /// escrows and none of its pending escrows can release.
    function setSessionPaused(uint256 sessionId, bool paused) external {
        Session storage s = _session(sessionId);
        if (msg.sender != s.payer) revert NotSessionPayer();
        if (s.revoked) revert SessionRevokedErr();
        s.paused = paused;
        emit SessionUpdated(sessionId, s.payer, s.operator, s.guardian, s.maxPerTx, s.capTotal, s.expiry, paused);
    }

    /// @notice Permanently revoke a session. New escrows are blocked and every
    /// pending escrow is frozen; the payer can still reclaim each one.
    function revokeSession(uint256 sessionId) external {
        Session storage s = _session(sessionId);
        if (msg.sender != s.payer) revert NotSessionPayer();
        if (s.revoked) revert SessionRevokedErr();
        s.revoked = true;
        emit SessionRevoked(sessionId, s.payer);
    }

    // ------------------------------------------------------------------
    // Escrow lifecycle
    // ------------------------------------------------------------------

    /// @notice Commitment that binds the risk score to the escrow parameters.
    /// Computed on chain so a caller cannot lower the score after attestation.
    function computeCommitment(
        uint256 sessionId,
        address payer,
        address recipient,
        uint256 amount,
        uint8 riskScore,
        bytes32 attestationHash,
        uint64 deadline
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                sessionId,
                payer,
                recipient,
                amount,
                riskScore,
                attestationHash,
                deadline
            )
        );
    }

    /// @notice Map a 0-100 exposure score to its release tier.
    function tierOf(uint8 score) public pure returns (Tier) {
        if (score > SCORE_CRITICAL_MAX) revert InvalidScore();
        if (score <= SCORE_LOW_MAX) return Tier.Low;
        if (score <= SCORE_MEDIUM_MAX) return Tier.Medium;
        if (score <= SCORE_HIGH_MAX) return Tier.High;
        return Tier.Critical;
    }

    /// @notice Fund an escrow under a session. The risk score is bound by the
    /// commitment hash and selects the release path at creation time.
    function createEscrow(
        uint256 sessionId,
        address recipient,
        uint256 amount,
        uint8 riskScore,
        bytes32 attestationHash,
        bytes32 commitmentHash,
        uint64 deadline
    ) external nonReentrant returns (uint256 escrowId) {
        Session storage s = _session(sessionId);
        if (s.revoked) revert SessionRevokedErr();
        if (s.paused) revert SessionPausedErr();
        if (block.timestamp >= s.expiry) revert SessionExpiredErr();
        if (msg.sender != s.payer && msg.sender != s.operator) revert NotSessionActor();
        if (recipient == address(0) || recipient == s.payer || recipient == address(this)) {
            revert InvalidRecipient();
        }
        if (amount == 0) revert InvalidAmount();
        if (amount > s.maxPerTx) revert PerTxCapExceeded();
        if (amount > s.capTotal - s.spent) revert CumulativeCapExceeded();
        if (riskScore > SCORE_CRITICAL_MAX) revert InvalidScore();
        if (attestationHash == bytes32(0) || commitmentHash == bytes32(0)) revert InvalidHash();
        if (deadline <= block.timestamp) revert InvalidDeadline();
        if (
            commitmentHash
                != computeCommitment(sessionId, s.payer, recipient, amount, riskScore, attestationHash, deadline)
        ) {
            revert CommitmentMismatch();
        }

        Tier tier = tierOf(riskScore);
        uint64 releaseNotBefore;
        if (tier == Tier.Low) {
            releaseNotBefore = uint64(block.timestamp);
        } else if (tier == Tier.Medium) {
            releaseNotBefore = uint64(block.timestamp) + s.mediumDelay;
        } else if (tier == Tier.High) {
            if (s.guardian == address(0)) revert HighTierNeedsGuardian();
            releaseNotBefore = uint64(block.timestamp) + s.highDelay;
        } else {
            releaseNotBefore = type(uint64).max; // quarantined marker
        }
        if (tier != Tier.Critical && deadline <= releaseNotBefore) revert DeadlineBeforeUnlock();

        // Effects before interaction.
        escrowId = nextEscrowId++;
        s.spent += amount;
        Escrow storage e = _escrows[escrowId];
        e.sessionId = sessionId;
        e.payer = s.payer;
        e.recipient = recipient;
        e.amount = amount;
        e.riskScore = riskScore;
        e.tier = tier;
        e.status = Status.Funded;
        e.attestationHash = attestationHash;
        e.commitmentHash = commitmentHash;
        e.createdAt = uint64(block.timestamp);
        e.deadline = deadline;
        e.releaseNotBefore = releaseNotBefore;

        emit EscrowCreated(
            escrowId,
            sessionId,
            s.payer,
            recipient,
            amount,
            riskScore,
            tier,
            releaseNotBefore,
            deadline,
            attestationHash,
            commitmentHash
        );

        // Interaction last: pull the exact escrowed amount from the payer.
        uint256 balBefore = token.balanceOf(address(this));
        _safeTransferFrom(s.payer, address(this), amount);
        if (token.balanceOf(address(this)) - balBefore != amount) revert TransferAmountMismatch();
    }

    /// @notice Guardian co-sign for a High tier escrow. Only the session
    /// guardian may call this, and only while the escrow is still funded.
    function guardianApprove(uint256 escrowId) external {
        Escrow storage e = _escrow(escrowId);
        if (e.status != Status.Funded) revert EscrowNotFunded();
        if (e.tier != Tier.High) revert EscrowNotHighTier();
        Session storage s = _sessions[e.sessionId];
        if (msg.sender != s.guardian) revert NotGuardian();
        e.guardianApproved = true;
        emit GuardianApproved(escrowId, msg.sender);
    }

    /// @notice Release escrowed funds to the recipient once the risk gate
    /// opens. Callable by anyone; the gate fully decides the outcome.
    function release(uint256 escrowId) external nonReentrant {
        Escrow storage e = _escrow(escrowId);
        if (e.status != Status.Funded) revert EscrowNotFunded();
        if (e.tier == Tier.Critical) revert Quarantined();

        Session storage s = _sessions[e.sessionId];
        if (s.revoked) revert SessionRevokedErr();
        if (s.paused) revert SessionPausedErr();
        if (block.timestamp >= s.expiry) revert SessionExpiredErr();
        if (block.timestamp > e.deadline) revert DeadlinePassed();
        if (block.timestamp < e.releaseNotBefore) revert TimelockActive(e.releaseNotBefore);
        if (e.tier == Tier.High && !e.guardianApproved) revert GuardianApprovalMissing();

        // Effects before interaction.
        e.status = Status.Released;
        emit EscrowReleased(escrowId, e.recipient, e.amount);

        _safeTransfer(e.recipient, e.amount);
    }

    /// @notice Payer side escape hatch. While an escrow is funded the payer can
    /// always cancel it and take the tokens back: during a Medium or High
    /// timelock window, after the deadline, or immediately for a quarantined
    /// Critical escrow.
    function revokeEscrow(uint256 escrowId) external nonReentrant {
        Escrow storage e = _escrow(escrowId);
        if (e.status != Status.Funded) revert EscrowNotFunded();
        if (msg.sender != e.payer) revert NotPayer();

        // Effects before interaction.
        e.status = Status.Revoked;
        emit EscrowRevoked(escrowId, e.payer, e.amount);

        _safeTransfer(e.payer, e.amount);
    }

    /// @notice Emergency batch rescue for a payer. Quantum key compromise is a
    /// fleet problem, not a single-payment problem: this revokes up to
    /// MAX_BATCH_REVOKE funded escrows in one transaction and returns the
    /// combined amount in one token transfer. The batch is strict and
    /// all-or-nothing; an unknown, duplicate, non-funded or foreign escrow id
    /// reverts the whole rescue instead of silently skipping a payment.
    function revokeEscrows(uint256[] calldata escrowIds) external nonReentrant {
        if (escrowIds.length == 0 || escrowIds.length > MAX_BATCH_REVOKE) revert InvalidBatchSize();
        uint256 totalAmount;
        for (uint256 i = 0; i < escrowIds.length; i++) {
            for (uint256 j = i + 1; j < escrowIds.length; j++) {
                if (escrowIds[i] == escrowIds[j]) revert DuplicateEscrowId();
            }
            Escrow storage probe = _escrow(escrowIds[i]);
            if (probe.status != Status.Funded) revert EscrowNotFunded();
            if (msg.sender != probe.payer) revert NotPayer();
        }

        // Effects before interaction. Individual events preserve the exact
        // audit trail produced by single revokes; the batch event records the
        // aggregate rescue for indexers.
        for (uint256 i = 0; i < escrowIds.length; i++) {
            Escrow storage e = _escrow(escrowIds[i]);
            e.status = Status.Revoked;
            totalAmount += e.amount;
            emit EscrowRevoked(escrowIds[i], e.payer, e.amount);
        }
        emit EscrowsBatchRevoked(msg.sender, escrowIds.length, totalAmount);

        _safeTransfer(msg.sender, totalAmount);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function getSession(uint256 sessionId) external view returns (Session memory) {
        return _sessions[sessionId];
    }

    function getEscrow(uint256 escrowId) external view returns (Escrow memory) {
        return _escrows[escrowId];
    }

    /// @notice Whether an escrow would currently pass release() gate checks.
    /// Mirrors the same branch order; useful for UI status readouts.
    function releaseBlocker(uint256 escrowId) external view returns (bytes32) {
        Escrow storage e = _escrow(escrowId);
        if (e.status != Status.Funded) return "not_funded";
        if (e.tier == Tier.Critical) return "quarantined";
        Session storage s = _sessions[e.sessionId];
        if (s.revoked) return "session_revoked";
        if (s.paused) return "session_paused";
        if (block.timestamp >= s.expiry) return "session_expired";
        if (block.timestamp > e.deadline) return "deadline_passed";
        if (block.timestamp < e.releaseNotBefore) return "timelock";
        if (e.tier == Tier.High && !e.guardianApproved) return "guardian";
        return bytes32(0);
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    function _session(uint256 sessionId) internal view returns (Session storage) {
        if (sessionId >= nextSessionId) revert SessionUnknown();
        return _sessions[sessionId];
    }

    function _escrow(uint256 escrowId) internal view returns (Escrow storage) {
        if (escrowId >= nextEscrowId) revert EscrowUnknown();
        return _escrows[escrowId];
    }

    /// @dev Low level ERC-20 transfer that tolerates tokens which omit the
    /// boolean return value and reverts on an explicit false or call failure.
    function _safeTransfer(address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeCall(IERC20.transfer, (to, amount)));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _safeTransferFrom(address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeCall(IERC20.transferFrom, (from, to, amount)));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}
