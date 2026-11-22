// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {PQPayGuardEscrow} from "../contracts/PQPayGuardEscrow.sol";
import {MockTUSD8} from "../contracts/MockTUSD8.sol";
import {ReentrantToken} from "../contracts/mocks/ReentrantToken.sol";

/// @dev Extended coverage: domain separation, replay resistance, cap and
/// expiry boundaries, guardian edge cases, gas bounds and event coverage.
contract PQPayGuardEscrowExtendedTest is TestBase {
    MockTUSD8 internal token;
    PQPayGuardEscrow internal escrow;

    address internal payer = address(0xA11CE);
    address internal operator = address(0xB0B);
    address internal guardian = address(0xCAAD);
    address internal guardian2 = address(0xCAFE);
    address internal recipient = address(0xDEAD);
    address internal recipient2 = address(0xBEEF);
    address internal rando = address(0xF00D);

    uint64 internal constant T0 = 1_760_000_000;
    uint64 internal constant MED = 900;
    uint64 internal constant HIGH = 4 * 3600;
    uint64 internal constant EXPIRY_D = 7 days;

    function setUp() public {
        vm.warp(T0);
        token = new MockTUSD8();
        escrow = new PQPayGuardEscrow(address(token));
        token.mint(payer, 1_000_000_000_000);
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
    }

    function _session() internal returns (uint256) {
        vm.prank(payer);
        return escrow.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
    }

    function _att() internal pure returns (bytes32) {
        return keccak256("pq-payguard-ext-attestation");
    }

    function _mkEscrow(uint256 sid, uint8 score) internal returns (uint256) {
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, score, att, dl);
        vm.prank(payer);
        return escrow.createEscrow(sid, recipient, 100_000_000, score, att, com, dl);
    }

    function _bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (lo > hi) return lo;
        return lo + (x % (hi - lo + 1));
    }

    // ---- domain separation --------------------------------------------------

    function testCommitmentDiffersAcrossChainIds() public {
        uint256 sid = _session();
        bytes32 att = _att();
        bytes32 cAevum = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, uint64(T0 + 1 days));
        vm.chainId(1);
        bytes32 cEth = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, uint64(T0 + 1 days));
        vm.chainId(44005);
        assertTrue(cAevum != cEth, "chainid must be inside the commitment domain");
    }

    function testCommitmentDiffersAcrossContracts() public {
        PQPayGuardEscrow escrow2 = new PQPayGuardEscrow(address(token));
        bytes32 att = _att();
        bytes32 c1 = escrow.computeCommitment(0, payer, recipient, 1, 10, att, uint64(T0 + 1 days));
        bytes32 c2 = escrow2.computeCommitment(0, payer, recipient, 1, 10, att, uint64(T0 + 1 days));
        assertTrue(c1 != c2, "contract address must be inside the commitment domain");
    }

    function testForeignChainReplayRejected() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 comAevum = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 10, att, dl);
        // attacker captures Aevum calldata and replays it after a chain hop
        vm.chainId(97);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.CommitmentMismatch.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, comAevum, dl);
        vm.chainId(44005);
    }

    function testCrossContractReplayRejected() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com1 = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 10, att, dl);

        PQPayGuardEscrow escrow2 = new PQPayGuardEscrow(address(token));
        vm.prank(payer);
        uint256 sid2 = escrow2.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        vm.prank(payer);
        token.approve(address(escrow2), type(uint256).max);

        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.CommitmentMismatch.selector);
        escrow2.createEscrow(sid2, recipient, 100_000_000, 10, att, com1, dl);
    }

    function testCommitmentBindsEveryField() public {
        uint256 sid = _session();
        bytes32 att = _att();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 base = escrow.computeCommitment(sid, payer, recipient, 7, 33, att, dl);
        assertTrue(base != escrow.computeCommitment(sid + 1, payer, recipient, 7, 33, att, dl), "sessionId");
        assertTrue(base != escrow.computeCommitment(sid, rando, recipient, 7, 33, att, dl), "payer");
        assertTrue(base != escrow.computeCommitment(sid, payer, recipient2, 7, 33, att, dl), "recipient");
        assertTrue(base != escrow.computeCommitment(sid, payer, recipient, 8, 33, att, dl), "amount");
        assertTrue(base != escrow.computeCommitment(sid, payer, recipient, 7, 34, att, dl), "score");
        assertTrue(base != escrow.computeCommitment(sid, payer, recipient, 7, 33, keccak256("other"), dl), "attestation");
        assertTrue(base != escrow.computeCommitment(sid, payer, recipient, 7, 33, att, dl + 1), "deadline");
    }

    function testCommitmentDeterministicView() public {
        uint256 sid = _session();
        bytes32 att = _att();
        bytes32 a = escrow.computeCommitment(sid, payer, recipient, 9, 10, att, uint64(T0 + 1 days));
        bytes32 b = escrow.computeCommitment(sid, payer, recipient, 9, 10, att, uint64(T0 + 1 days));
        assertEq(a, b, "commitment view is deterministic");
    }

    // ---- replay / double spend edges ------------------------------------------

    function testDoubleReleaseRejected() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        escrow.release(eid);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotFunded.selector);
        escrow.release(eid);
    }

    function testDoubleRevokeRejected() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.prank(payer);
        escrow.revokeEscrow(eid);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotFunded.selector);
        escrow.revokeEscrow(eid);
    }

    function testGuardianApproveAfterReleaseReverts() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(guardian);
        escrow.guardianApprove(eid);
        vm.warp(T0 + HIGH);
        escrow.release(eid);
        vm.prank(guardian);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotFunded.selector);
        escrow.guardianApprove(eid);
    }

    function testGuardianApproveIdempotent() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(guardian);
        escrow.guardianApprove(eid);
        vm.prank(guardian);
        escrow.guardianApprove(eid); // second approve is a no-op, not a revert
        assertTrue(escrow.getEscrow(eid).guardianApproved, "still approved");
    }

    function testVerbatimCreateReplayCannotRedirect() public {
        uint256 sid = _session();
        uint256 eid1 = _mkEscrow(sid, 10);
        // an identical calldata replay funds a NEW escrow id bound to the
        // same recipient - no redirection is possible
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 10, att, dl);
        vm.prank(payer);
        uint256 eid2 = escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
        assertTrue(eid2 != eid1, "replay mints a new id");
        assertEq(escrow.getEscrow(eid2).recipient, recipient, "same bound recipient");
        assertEq(token.balanceOf(address(escrow)), 200_000_000, "both funded, none drained");
    }

    // ---- cap exhaustion boundaries ------------------------------------------------

    function testPerTxCapExactBoundary() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 500_000_000, 10, att, dl);
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 500_000_000, 10, att, com, dl);
        assertEq(escrow.getEscrow(eid).amount, 500_000_000, "exact cap accepted");
    }

    function testPerTxCapPlusOneReverts() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 500_000_001, 10, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.PerTxCapExceeded.selector);
        escrow.createEscrow(sid, recipient, 500_000_001, 10, att, com, dl);
    }

    function testCumulativeCapExactBoundary() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), guardian, 500_000_000, 1_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        _mkEscrow(sid, 10); // 100M
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 400_000_000, 10, att, dl);
        vm.prank(payer);
        escrow.createEscrow(sid, recipient, 400_000_000, 10, att, com, dl); // 500M of 1000M
        bytes32 com2 = escrow.computeCommitment(sid, payer, recipient, 500_000_000, 10, att, dl);
        vm.prank(payer);
        escrow.createEscrow(sid, recipient, 500_000_000, 10, att, com2, dl); // exactly 1000M
        assertEq(escrow.getSession(sid).spent, 1_000_000_000, "cap fully consumed");
        bytes32 com3 = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.CumulativeCapExceeded.selector);
        escrow.createEscrow(sid, recipient, 1, 10, att, com3, dl);
    }

    function testSpentSurvivesSessionRevoke() public {
        uint256 sid = _session();
        _mkEscrow(sid, 10);
        vm.prank(payer);
        escrow.revokeSession(sid);
        assertEq(escrow.getSession(sid).spent, 100_000_000, "spent accounting preserved");
    }

    function testMultipleSessionsIndependent() public {
        uint256 sid1 = _session();
        uint256 sid2 = _session();
        vm.prank(payer);
        escrow.setSessionPaused(sid1, true);
        // session 2 unaffected by session 1 pause
        uint256 eid = _mkEscrow(sid2, 10);
        escrow.release(eid);
        assertEq(token.balanceOf(recipient), 100_000_000, "independent session still pays");
        assertEq(escrow.getSession(sid1).spent, 0, "paused session spent nothing");
        assertEq(escrow.getSession(sid2).spent, 100_000_000, "active tracked");
    }

    // ---- expiry boundaries ----------------------------------------------------------

    function testExpiryBoundaryCreateAndRelease() public {
        uint256 sid = _session();
        // long deadline so the escrow stays releasable right up to expiry
        uint64 dl = uint64(T0 + EXPIRY_D + 1 days);
        bytes32 att = _att();
        bytes32 com0 = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 10, att, dl);
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com0, dl);
        vm.warp(T0 + EXPIRY_D - 1);
        escrow.release(eid); // last second still fine
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, dl);
        vm.prank(payer);
        escrow.createEscrow(sid, recipient, 1, 10, att, com, dl); // still inside
        vm.warp(T0 + EXPIRY_D);
        bytes32 com2 = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.SessionExpiredErr.selector);
        escrow.createEscrow(sid, recipient, 1, 10, att, com2, dl);
    }

    function testDeadlineEqualNowReverts() public {
        uint256 sid = _session();
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, uint64(T0));
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidDeadline.selector);
        escrow.createEscrow(sid, recipient, 1, 10, att, com, uint64(T0));
    }

    function testDeadlineExactlyAtUnlockReverts() public {
        uint256 sid = _session(); // medium delay 900
        uint64 dl = uint64(T0 + MED);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.DeadlineBeforeUnlock.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);
    }

    function testDeadlineOneSecondAfterUnlockAccepted() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + MED + 1);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);
        assertEq(escrow.getEscrow(eid).deadline, dl, "accepted");
    }

    // ---- guardian / recovery edge cases -------------------------------------------------

    function testGuardianApproveOnRevokedSessionStillWorks() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(payer);
        escrow.revokeSession(sid);
        // approval itself is not session gated; release still is
        vm.prank(guardian);
        escrow.guardianApprove(eid);
        assertTrue(escrow.getEscrow(eid).guardianApproved, "approval recorded");
        vm.warp(T0 + HIGH);
        vm.expectRevert(PQPayGuardEscrow.SessionRevokedErr.selector);
        escrow.release(eid);
    }

    function testGuardianApproveAfterDeadlineStillBlocked() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(guardian);
        escrow.guardianApprove(eid);
        vm.warp(T0 + 2 days); // past the 1 day deadline
        vm.expectRevert(PQPayGuardEscrow.DeadlinePassed.selector);
        escrow.release(eid);
    }

    function testGuardianCannotApproveOthersSession() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), guardian2, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(guardian); // guardian of a different session
        vm.expectRevert(PQPayGuardEscrow.NotGuardian.selector);
        escrow.guardianApprove(eid);
        vm.prank(guardian2);
        escrow.guardianApprove(eid);
        assertTrue(escrow.getEscrow(eid).guardianApproved, "right guardian works");
    }

    function testRecipientCannotSelfApprove() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(recipient);
        vm.expectRevert(PQPayGuardEscrow.NotGuardian.selector);
        escrow.guardianApprove(eid);
    }

    function testPayerCannotApproveAsGuardian() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.NotGuardian.selector);
        escrow.guardianApprove(eid);
    }

    function testCriticalReclaimAlwaysAvailable() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 95);
        vm.warp(T0 + 365 days);
        uint256 before = token.balanceOf(payer);
        vm.prank(payer);
        escrow.revokeEscrow(eid); // session long expired; reclaim still open
        assertEq(token.balanceOf(payer) - before, 100_000_000, "quarantined funds recoverable");
    }

    function testOperatorCannotAdministerSession() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            operator, guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        vm.prank(operator);
        vm.expectRevert(PQPayGuardEscrow.NotSessionPayer.selector);
        escrow.setSessionPaused(sid, true);
        vm.prank(operator);
        vm.expectRevert(PQPayGuardEscrow.NotSessionPayer.selector);
        escrow.revokeSession(sid);
    }

    function testOperatorCanFundWithinCapsOnly() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            operator, guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        // operator funds the payer's session, payer's tokens are pulled
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 500_000_000, 10, att, dl);
        vm.prank(operator);
        escrow.createEscrow(sid, recipient, 500_000_000, 10, att, com, dl);
        bytes32 com2 = escrow.computeCommitment(sid, payer, recipient, 1, 10, att, dl);
        vm.prank(operator);
        vm.expectRevert(PQPayGuardEscrow.PerTxCapExceeded.selector);
        escrow.createEscrow(sid, recipient, 500_000_001, 10, att, com2, dl);
    }

    // ---- session param edges ------------------------------------------------------------

    function testSessionIdsIncrement() public {
        uint256 s1 = _session();
        uint256 s2 = _session();
        uint256 s3 = _session();
        assertEq(s1 + 1, s2, "sequential");
        assertEq(s2 + 1, s3, "sequential");
    }

    function testEscrowIdsIncrementAcrossSessions() public {
        uint256 s1 = _session();
        uint256 s2 = _session();
        uint256 e1 = _mkEscrow(s1, 10);
        uint256 e2 = _mkEscrow(s2, 10);
        assertEq(e1 + 1, e2, "global escrow id space");
    }

    function testZeroOperatorZeroGuardianSession() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), address(0), 1, 1, uint64(T0 + 1), 0, 0
        );
        PQPayGuardEscrow.Session memory s = escrow.getSession(sid);
        assertEq(s.operator, address(0), "no operator");
        assertEq(s.guardian, address(0), "no guardian");
    }

    function testMaxDelayBoundaryAccepted() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), guardian, 1, 1, uint64(T0 + 60 days), 30 days, 30 days
        );
        assertEq(escrow.getSession(sid).highDelay, 30 days, "30d accepted");
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(
            address(0), guardian, 1, 1, uint64(T0 + 60 days), 30 days + 1, 30 days + 1
        );
    }

    function testExpiryEqualNowReverts() public {
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), guardian, 1, 1, uint64(T0), 0, 0);
    }

    // ---- release ordering edges -------------------------------------------------------------

    function testQuarantineCheckPrecedesSessionChecks() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 95);
        vm.prank(payer);
        escrow.revokeSession(sid);
        // quarantined outranks session state in the gate order
        vm.expectRevert(PQPayGuardEscrow.Quarantined.selector);
        escrow.release(eid);
    }

    function testDeadlineCheckBeforeTimelock() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + MED + 1);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);
        vm.warp(dl + 5); // inside the would-be unlock... no, past deadline
        vm.expectRevert(PQPayGuardEscrow.DeadlinePassed.selector);
        escrow.release(eid);
    }

    function testReleaseBlockerFullVocabulary() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        assertEq(escrow.releaseBlocker(eid), bytes32("timelock"), "timelock");
        vm.prank(payer);
        escrow.setSessionPaused(sid, true);
        assertEq(escrow.releaseBlocker(eid), bytes32("session_paused"), "paused");
        vm.prank(payer);
        escrow.setSessionPaused(sid, false);
        vm.warp(T0 + MED);
        assertEq(escrow.releaseBlocker(eid), bytes32(0), "open");
        vm.warp(T0 + 2 days);
        assertEq(escrow.releaseBlocker(eid), bytes32("deadline_passed"), "deadline");
        vm.prank(payer);
        escrow.revokeEscrow(eid);
        assertEq(escrow.releaseBlocker(eid), bytes32("not_funded"), "not_funded");
    }

    // ---- token flow edges ---------------------------------------------------------------------

    function testExactBalanceDeltaOnCreate() public {
        uint256 sid = _session();
        uint256 balBefore = token.balanceOf(address(escrow));
        _mkEscrow(sid, 10);
        assertEq(token.balanceOf(address(escrow)) - balBefore, 100_000_000, "exact pull");
    }

    function testInsufficientBalanceReverts() public {
        address broke = address(0xBAD);
        vm.prank(broke);
        token.mint(broke, 1);
        vm.prank(broke);
        uint256 sid = escrow.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        vm.prank(broke);
        token.approve(address(escrow), type(uint256).max);
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, broke, recipient, 2, 10, att, dl);
        vm.prank(broke);
        vm.expectRevert(PQPayGuardEscrow.TransferFailed.selector);
        escrow.createEscrow(sid, recipient, 2, 10, att, com, dl);
    }

    function testPartialAllowanceReverts() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 10, att, dl);
        vm.prank(payer);
        token.approve(address(escrow), 99_999_999); // one unit short
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.TransferFailed.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
    }

    function testReentrancyOnRevoke() public {
        ReentrantToken evil = new ReentrantToken();
        PQPayGuardEscrow escrow2 = new PQPayGuardEscrow(address(evil));
        evil.mint(payer, 1_000_000);
        vm.prank(payer);
        evil.approve(address(escrow2), type(uint256).max);
        evil.setEscrow(address(escrow2));
        vm.prank(payer);
        uint256 sid = escrow2.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow2.computeCommitment(sid, payer, recipient, 100_000, 10, att, dl);
        vm.prank(payer);
        uint256 eid = escrow2.createEscrow(sid, recipient, 100_000, 10, att, com, dl);
        evil.setAttack(eid, true, false);
        vm.prank(payer);
        escrow2.revokeEscrow(eid); // refund path reentry blocked too
        assertEq(evil.balanceOf(payer), 1_000_000, "single refund only");
    }

    // ---- gas bounds ---------------------------------------------------------------------------

    function testGasCreateSession() public {
        uint256 g0 = gasleft();
        vm.prank(payer);
        escrow.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint256 used = g0 - gasleft();
        assertTrue(used < 250_000, "createSession gas bound");
    }

    function testGasCreateEscrow() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, 10, att, dl);
        uint256 g0 = gasleft();
        vm.prank(payer);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
        uint256 used = g0 - gasleft();
        assertTrue(used < 350_000, "createEscrow gas bound");
    }

    function testGasReleaseLowTier() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        uint256 g0 = gasleft();
        escrow.release(eid);
        uint256 used = g0 - gasleft();
        assertTrue(used < 120_000, "release gas bound");
    }

    function testGasRevokeEscrow() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        uint256 g0 = gasleft();
        vm.prank(payer);
        escrow.revokeEscrow(eid);
        uint256 used = g0 - gasleft();
        assertTrue(used < 120_000, "revoke gas bound");
    }

    function testGasGuardianApprove() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        uint256 g0 = gasleft();
        vm.prank(guardian);
        escrow.guardianApprove(eid);
        uint256 used = g0 - gasleft();
        assertTrue(used < 80_000, "guardianApprove gas bound");
    }

    // ---- events --------------------------------------------------------------------------------

    function testSessionRevokedEvent() public {
        uint256 sid = _session();
        vm.expectEmit(true, true, false, false);
        emit PQPayGuardEscrow.SessionRevoked(sid, payer);
        vm.prank(payer);
        escrow.revokeSession(sid);
    }

    function testGuardianApprovedEvent() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.expectEmit(true, true, false, false);
        emit PQPayGuardEscrow.GuardianApproved(eid, guardian);
        vm.prank(guardian);
        escrow.guardianApprove(eid);
    }

    function testEscrowRevokedEvent() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.expectEmit(true, true, false, true);
        emit PQPayGuardEscrow.EscrowRevoked(eid, payer, 100_000_000);
        vm.prank(payer);
        escrow.revokeEscrow(eid);
    }

    function testSessionPausedEvent() public {
        uint256 sid = _session();
        vm.expectEmit(true, true, false, true);
        emit PQPayGuardEscrow.SessionUpdated(
            sid, payer, address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), true
        );
        vm.prank(payer);
        escrow.setSessionPaused(sid, true);
    }

    // ---- fuzz ------------------------------------------------------------------------------------

    function testFuzzDomainSeparation(uint64 otherChain) public {
        vm.assume(otherChain != 44005);
        bytes32 att = _att();
        bytes32 cA = escrow.computeCommitment(0, payer, recipient, 5, 10, att, uint64(T0 + 1 days));
        vm.chainId(otherChain);
        bytes32 cB = escrow.computeCommitment(0, payer, recipient, 5, 10, att, uint64(T0 + 1 days));
        vm.chainId(44005);
        assertTrue(cA != cB, "any foreign chain id must change the commitment");
    }

    function testFuzzAmountBoundaries(uint256 amount) public {
        amount = _bound(amount, 1, 2_000_000_000);
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, amount, 10, att, dl);
        vm.prank(payer);
        if (amount > 500_000_000) {
            vm.expectRevert(PQPayGuardEscrow.PerTxCapExceeded.selector);
            escrow.createEscrow(sid, recipient, amount, 10, att, com, dl);
        } else {
            uint256 eid = escrow.createEscrow(sid, recipient, amount, 10, att, com, dl);
            assertEq(escrow.getEscrow(eid).amount, amount, "funded exact");
        }
    }

    function testFuzzCommitmentSensitivity(uint8 score, uint256 amount, uint64 dl) public {
        vm.assume(score <= 100);
        amount = _bound(amount, 0, type(uint128).max);
        vm.assume(dl > uint64(T0) && dl < type(uint64).max);
        bytes32 att = _att();
        bytes32 c1 = escrow.computeCommitment(0, payer, recipient, amount, score, att, dl);
        // any single-field perturbation changes the digest
        bytes32 c2 = escrow.computeCommitment(0, payer, recipient, amount + 1, score, att, dl);
        assertTrue(c1 != c2, "amount +1 changes commitment");
    }

    function testFuzzHighDelayOrdering(uint64 med, uint64 high) public {
        med = uint64(_bound(med, 0, 30 days));
        high = uint64(_bound(high, 0, 30 days));
        vm.prank(payer);
        if (high < med) {
            vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
            escrow.createSession(
                address(0), guardian, 1, 1, uint64(T0 + 60 days), med, high
            );
        } else {
            uint256 sid = escrow.createSession(
                address(0), guardian, 1, 1, uint64(T0 + 60 days), med, high
            );
            assertEq(escrow.getSession(sid).highDelay, high, "stored");
        }
    }

    function testFuzzReleaseWindow(uint64 warpTo) public {
        warpTo = uint64(_bound(warpTo, 0, 60 days));
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45); // medium, 900s delay, 1d deadline
        vm.warp(T0 + warpTo);
        if (warpTo >= MED && warpTo <= 1 days) {
            escrow.release(eid);
            assertEq(uint8(escrow.getEscrow(eid).status), uint8(PQPayGuardEscrow.Status.Released), "released");
        } else {
            vm.expectRevert();
            escrow.release(eid);
        }
    }

    function testFuzzScoreTierExhaustiveParity(uint8 score) public {
        vm.assume(score <= 100);
        uint8 t = uint8(escrow.tierOf(score));
        uint8 want = score <= 29 ? 0 : score <= 59 ? 1 : score <= 84 ? 2 : 3;
        assertEq(t, want, "tier table parity");
    }

    function testFuzzNonPayerCannotPause(address caller) public {
        vm.assume(caller != payer && caller != address(0));
        uint256 sid = _session();
        vm.prank(caller);
        vm.expectRevert(PQPayGuardEscrow.NotSessionPayer.selector);
        escrow.setSessionPaused(sid, true);
    }

    function testFuzzNonGuardianCannotApprove(address caller) public {
        vm.assume(caller != guardian);
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.prank(caller);
        vm.expectRevert(PQPayGuardEscrow.NotGuardian.selector);
        escrow.guardianApprove(eid);
    }

    function testFuzzNonPayerCannotRevoke(address caller) public {
        vm.assume(caller != payer);
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.prank(caller);
        vm.expectRevert(PQPayGuardEscrow.NotPayer.selector);
        escrow.revokeEscrow(eid);
    }
}
