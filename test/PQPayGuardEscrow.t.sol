// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {PQPayGuardEscrow} from "../contracts/PQPayGuardEscrow.sol";
import {MockTUSD8} from "../contracts/MockTUSD8.sol";
import {ReentrantToken} from "../contracts/mocks/ReentrantToken.sol";

contract PQPayGuardEscrowTest is TestBase {
    MockTUSD8 internal token;
    PQPayGuardEscrow internal escrow;

    address internal payer = address(0xA11CE);
    address internal operator = address(0xB0B);
    address internal guardian = address(0xCAAD);
    address internal recipient = address(0xDEAD);
    address internal rando = address(0xF00D);

    uint64 internal constant T0 = 1_760_000_000;
    uint64 internal constant MED = 900;
    uint64 internal constant HIGH = 4 * 3600;
    uint64 internal constant EXPIRY_D = 7 days;

    function setUp() public {
        vm.warp(T0);
        token = new MockTUSD8();
        escrow = new PQPayGuardEscrow(address(token));
        token.mint(payer, 1_000_000_000_000); // 1,000,000.000000 tUSD8
        vm.prank(payer);
        token.approve(address(escrow), type(uint256).max);
    }

    // ---- helpers -------------------------------------------------------

    function _session() internal returns (uint256) {
        vm.prank(payer);
        return escrow.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
    }

    function _commit(
        uint256 sid,
        address rec,
        uint256 amt,
        uint8 score,
        bytes32 att,
        uint64 deadline
    ) internal view returns (bytes32) {
        return escrow.computeCommitment(sid, payer, rec, amt, score, att, deadline);
    }

    function _att() internal pure returns (bytes32) {
        return keccak256("pq-payguard-test-attestation");
    }

    function _mkEscrow(uint256 sid, uint8 score) internal returns (uint256) {
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, score, att, dl);
        vm.prank(payer);
        return escrow.createEscrow(sid, recipient, 100_000_000, score, att, com, dl);
    }

    // ---- session administration -----------------------------------------

    function testCreateSessionStoresPolicy() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            operator, guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        assertEq(sid, 0, "first session id");
        PQPayGuardEscrow.Session memory s = escrow.getSession(sid);
        assertEq(s.payer, payer, "payer");
        assertEq(s.operator, operator, "operator");
        assertEq(s.guardian, guardian, "guardian");
        assertEq(s.maxPerTx, 500_000_000, "maxPerTx");
        assertEq(s.capTotal, 2_000_000_000, "capTotal");
        assertEq(s.expiry, uint64(T0 + EXPIRY_D), "expiry");
        assertEq(s.mediumDelay, MED, "mediumDelay");
        assertEq(s.highDelay, HIGH, "highDelay");
        assertFalse(s.paused, "paused");
        assertFalse(s.revoked, "revoked");
    }

    function testCreateSessionRejectsBadParams() public {
        vm.startPrank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), guardian, 0, 100, uint64(T0 + 100), MED, HIGH);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), guardian, 100, 50, uint64(T0 + 100), MED, HIGH);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), guardian, 100, 100, uint64(T0 - 1), MED, HIGH);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), guardian, 100, 100, uint64(T0 + 100), 31 days, HIGH);
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), guardian, 100, 100, uint64(T0 + 100), HIGH, MED); // high < medium
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(payer, guardian, 100, 100, uint64(T0 + 100), MED, HIGH); // operator == payer
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(address(0), payer, 100, 100, uint64(T0 + 100), MED, HIGH); // guardian == payer
        vm.expectRevert(PQPayGuardEscrow.InvalidSessionParams.selector);
        escrow.createSession(operator, operator, 100, 100, uint64(T0 + 100), MED, HIGH); // guardian == operator
        vm.stopPrank();
    }

    function testPauseAndRevokeSession() public {
        uint256 sid = _session();
        vm.prank(rando);
        vm.expectRevert(PQPayGuardEscrow.NotSessionPayer.selector);
        escrow.setSessionPaused(sid, true);

        vm.startPrank(payer);
        escrow.setSessionPaused(sid, true);
        assertTrue(escrow.getSession(sid).paused, "paused set");
        escrow.setSessionPaused(sid, false);
        assertFalse(escrow.getSession(sid).paused, "paused cleared");

        escrow.revokeSession(sid);
        assertTrue(escrow.getSession(sid).revoked, "revoked set");
        vm.expectRevert(PQPayGuardEscrow.SessionRevokedErr.selector);
        escrow.setSessionPaused(sid, true);
        vm.expectRevert(PQPayGuardEscrow.SessionRevokedErr.selector);
        escrow.revokeSession(sid);
        vm.stopPrank();

        vm.prank(rando);
        vm.expectRevert(PQPayGuardEscrow.NotSessionPayer.selector);
        escrow.revokeSession(sid); // payer check runs before the revoked check
    }

    function testRevokeSessionWrongCaller() public {
        uint256 sid = _session();
        vm.prank(rando);
        vm.expectRevert(PQPayGuardEscrow.NotSessionPayer.selector);
        escrow.revokeSession(sid);
    }

    function testSessionUnknownReverts() public {
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.SessionUnknown.selector);
        escrow.setSessionPaused(999, true);
    }

    // ---- escrow creation gate -------------------------------------------

    function testCreateLowTierEscrow() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 10, att, dl);

        uint256 balBefore = token.balanceOf(address(escrow));
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);

        assertEq(eid, 0, "first escrow id");
        PQPayGuardEscrow.Escrow memory e = escrow.getEscrow(eid);
        assertEq(e.payer, payer, "payer");
        assertEq(e.recipient, recipient, "recipient");
        assertEq(e.amount, 100_000_000, "amount");
        assertEq(e.riskScore, 10, "score");
        assertEq(uint8(e.tier), uint8(PQPayGuardEscrow.Tier.Low), "tier low");
        assertEq(uint8(e.status), uint8(PQPayGuardEscrow.Status.Funded), "funded");
        assertEq(e.releaseNotBefore, uint64(T0), "instant unlock");
        assertEq(e.attestationHash, att, "att hash");
        assertEq(e.commitmentHash, com, "commitment");
        assertEq(token.balanceOf(address(escrow)) - balBefore, 100_000_000, "escrow funded");
        assertEq(token.balanceOf(payer), 999_900_000_000, "payer debited");
        assertEq(escrow.getSession(sid).spent, 100_000_000, "spent");
    }

    function testCreateEscrowTierUnlockTimes() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();

        bytes32 c1 = _commit(sid, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        uint256 e1 = escrow.createEscrow(sid, recipient, 100_000_000, 45, att, c1, dl);
        assertEq(escrow.getEscrow(e1).releaseNotBefore, uint64(T0 + MED), "medium unlock");

        bytes32 c2 = _commit(sid, recipient, 100_000_000, 70, att, dl);
        vm.prank(payer);
        uint256 e2 = escrow.createEscrow(sid, recipient, 100_000_000, 70, att, c2, dl);
        assertEq(escrow.getEscrow(e2).releaseNotBefore, uint64(T0 + HIGH), "high unlock");

        bytes32 c3 = _commit(sid, recipient, 100_000_000, 90, att, dl);
        vm.prank(payer);
        uint256 e3 = escrow.createEscrow(sid, recipient, 100_000_000, 90, att, c3, dl);
        assertEq(escrow.getEscrow(e3).releaseNotBefore, type(uint64).max, "quarantine marker");
    }

    function testCommitmentMismatchReverts() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        // commitment computed for score 80 but caller passes 20
        bytes32 com = _commit(sid, recipient, 100_000_000, 80, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.CommitmentMismatch.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 20, att, com, dl);
    }

    function testCreateEscrowValidationErrors() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        uint64 nowTs = uint64(block.timestamp);

        // Commitments are view calls on the escrow itself, so they must be
        // computed before expectRevert, which latches the next external call.
        bytes32 cZeroRec = _commit(sid, address(0), 100_000_000, 10, att, dl);
        bytes32 cPayerRec = _commit(sid, payer, 100_000_000, 10, att, dl);
        bytes32 cZeroAmt = _commit(sid, recipient, 0, 10, att, dl);
        bytes32 cOverTx = _commit(sid, recipient, 600_000_000, 10, att, dl);
        bytes32 cBadScore = _commit(sid, recipient, 100_000_000, 101, att, dl);
        bytes32 cZeroAtt = _commit(sid, recipient, 100_000_000, 10, bytes32(0), dl);
        bytes32 cBadDl = _commit(sid, recipient, 100_000_000, 10, att, nowTs);

        vm.startPrank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidRecipient.selector);
        escrow.createEscrow(sid, address(0), 100_000_000, 10, att, cZeroRec, dl);
        vm.expectRevert(PQPayGuardEscrow.InvalidRecipient.selector);
        escrow.createEscrow(sid, payer, 100_000_000, 10, att, cPayerRec, dl);
        vm.expectRevert(PQPayGuardEscrow.InvalidAmount.selector);
        escrow.createEscrow(sid, recipient, 0, 10, att, cZeroAmt, dl);
        vm.expectRevert(PQPayGuardEscrow.PerTxCapExceeded.selector);
        escrow.createEscrow(sid, recipient, 600_000_000, 10, att, cOverTx, dl);
        vm.expectRevert(PQPayGuardEscrow.InvalidScore.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 101, att, cBadScore, dl);
        vm.expectRevert(PQPayGuardEscrow.InvalidHash.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, bytes32(0), cZeroAtt, dl);
        vm.expectRevert(PQPayGuardEscrow.InvalidHash.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, bytes32(0), dl);
        vm.expectRevert(PQPayGuardEscrow.InvalidDeadline.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, cBadDl, nowTs);
        vm.stopPrank();
    }

    function testCumulativeCapExceeded() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), guardian, 500_000_000, 800_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        _mkEscrow(sid, 10); // 100M spent
        _mkEscrow(sid, 10); // 200M
        // third one still fine at 300M
        _mkEscrow(sid, 10);
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 400_000_000, 10, att, dl);
        vm.prank(payer);
        escrow.createEscrow(sid, recipient, 400_000_000, 10, att, com, dl); // 700M
        bytes32 com2 = _commit(sid, recipient, 200_000_000, 10, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.CumulativeCapExceeded.selector);
        escrow.createEscrow(sid, recipient, 200_000_000, 10, att, com2, dl); // 900M > 800M
    }

    function testHighTierNeedsGuardian() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), address(0), 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 70, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.HighTierNeedsGuardian.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 70, att, com, dl);
    }

    function testDeadlineBeforeUnlockReverts() public {
        uint256 sid = _session(); // medium delay 15 min
        uint64 dl = uint64(T0 + 300); // deadline 5 min < 15 min delay
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.DeadlineBeforeUnlock.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);
    }

    function testCreateOnPausedRevokedExpiredSession() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 10, att, dl);

        vm.startPrank(payer);
        escrow.setSessionPaused(sid, true);
        vm.expectRevert(PQPayGuardEscrow.SessionPausedErr.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
        escrow.setSessionPaused(sid, false);
        vm.stopPrank();

        // expired
        vm.warp(T0 + EXPIRY_D + 1);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.SessionExpiredErr.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
        vm.warp(T0);

        vm.startPrank(payer);
        escrow.revokeSession(sid);
        vm.expectRevert(PQPayGuardEscrow.SessionRevokedErr.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
        vm.stopPrank();
    }

    function testOperatorCreatesEscrow() public {
        vm.prank(payer);
        uint256 sid = escrow.createSession(
            operator, guardian, 500_000_000, 2_000_000_000, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 10, att, dl);
        vm.prank(operator);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
        assertEq(escrow.getEscrow(eid).payer, payer, "payer is session owner");
        assertEq(token.balanceOf(address(escrow)), 100_000_000, "tokens pulled from payer");

        vm.prank(rando);
        vm.expectRevert(PQPayGuardEscrow.NotSessionActor.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
    }

    function testTransferWithoutAllowanceReverts() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        vm.prank(payer);
        token.approve(address(escrow), 0); // strip allowance
        bytes32 com = _commit(sid, recipient, 100_000_000, 10, att, dl);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.TransferFailed.selector);
        escrow.createEscrow(sid, recipient, 100_000_000, 10, att, com, dl);
    }

    // ---- release gate ----------------------------------------------------

    function testReleaseLowTierInstant() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        vm.prank(recipient);
        escrow.release(eid); // anyone may trigger
        assertEq(uint8(escrow.getEscrow(eid).status), uint8(PQPayGuardEscrow.Status.Released), "released");
        assertEq(token.balanceOf(recipient), 100_000_000, "recipient paid");
        assertEq(token.balanceOf(address(escrow)), 0, "escrow emptied");
    }

    function testReleaseTwiceReverts() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        escrow.release(eid);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotFunded.selector);
        escrow.release(eid);
    }

    function testMediumTimelockGate() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.expectRevert(abi.encodeWithSelector(PQPayGuardEscrow.TimelockActive.selector, uint64(T0 + MED)));
        escrow.release(eid);

        vm.warp(T0 + MED - 1);
        vm.expectRevert();
        escrow.release(eid);

        vm.warp(T0 + MED);
        escrow.release(eid);
        assertEq(token.balanceOf(recipient), 100_000_000, "released after delay");
    }

    function testHighTierGuardianCosign() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);

        // wrong guardian
        vm.prank(rando);
        vm.expectRevert(PQPayGuardEscrow.NotGuardian.selector);
        escrow.guardianApprove(eid);

        // guardian approves but delay still gates
        vm.prank(guardian);
        escrow.guardianApprove(eid);
        assertTrue(escrow.getEscrow(eid).guardianApproved, "approved flag");

        vm.warp(T0 + HIGH - 1);
        vm.expectRevert();
        escrow.release(eid);

        vm.warp(T0 + HIGH);
        escrow.release(eid);
        assertEq(token.balanceOf(recipient), 100_000_000, "high released");
    }

    function testHighTierReleaseNeedsApproval() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 70);
        vm.warp(T0 + HIGH);
        vm.expectRevert(PQPayGuardEscrow.GuardianApprovalMissing.selector);
        escrow.release(eid);
    }

    function testGuardianApproveOnlyHigh() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10); // low tier
        vm.prank(guardian);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotHighTier.selector);
        escrow.guardianApprove(eid);
    }

    function testCriticalNeverReleases() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 95);
        vm.expectRevert(PQPayGuardEscrow.Quarantined.selector);
        escrow.release(eid);
        vm.warp(T0 + 365 days); // session expiry now passed, still quarantined
        vm.expectRevert(PQPayGuardEscrow.Quarantined.selector);
        escrow.release(eid);
    }

    function testReleaseAfterDeadlineReverts() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + MED + 100); // just past the unlock
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);
        vm.warp(dl + 1);
        vm.expectRevert(PQPayGuardEscrow.DeadlinePassed.selector);
        escrow.release(eid);
    }

    function testReleaseBlockedBySessionState() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);

        vm.startPrank(payer);
        escrow.setSessionPaused(sid, true);
        vm.expectRevert(PQPayGuardEscrow.SessionPausedErr.selector);
        escrow.release(eid);
        escrow.setSessionPaused(sid, false);

        escrow.revokeSession(sid);
        vm.expectRevert(PQPayGuardEscrow.SessionRevokedErr.selector);
        escrow.release(eid);
        vm.stopPrank();
    }

    function testReleaseBlockedBySessionExpiry() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        vm.warp(T0 + EXPIRY_D); // at expiry boundary
        vm.expectRevert(PQPayGuardEscrow.SessionExpiredErr.selector);
        escrow.release(eid);
    }

    // ---- payer revoke / reclaim ------------------------------------------

    function testPayerRevokesDuringMediumWindow() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.warp(T0 + 10);
        uint256 before = token.balanceOf(payer);
        vm.prank(payer);
        escrow.revokeEscrow(eid);
        assertEq(uint8(escrow.getEscrow(eid).status), uint8(PQPayGuardEscrow.Status.Revoked), "revoked");
        assertEq(token.balanceOf(payer) - before, 100_000_000, "refunded");
        assertEq(token.balanceOf(address(escrow)), 0, "emptied");
    }

    function testRevokeOnlyPayer() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.prank(rando);
        vm.expectRevert(PQPayGuardEscrow.NotPayer.selector);
        escrow.revokeEscrow(eid);
        vm.prank(recipient);
        vm.expectRevert(PQPayGuardEscrow.NotPayer.selector);
        escrow.revokeEscrow(eid);
    }

    function testCriticalImmediateReclaim() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 95);
        uint256 before = token.balanceOf(payer);
        vm.prank(payer);
        escrow.revokeEscrow(eid); // instant reclaim, no wait
        assertEq(token.balanceOf(payer) - before, 100_000_000, "reclaimed");
    }

    function testReclaimAfterDeadline() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        vm.warp(T0 + 2 days);
        vm.prank(payer);
        escrow.revokeEscrow(eid);
        assertEq(token.balanceOf(payer), 1_000_000_000_000, "full refund");
    }

    function testRevokeAfterReleaseReverts() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        escrow.release(eid);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotFunded.selector);
        escrow.revokeEscrow(eid);
    }

    function testEscrowUnknownReverts() public {
        vm.expectRevert(PQPayGuardEscrow.EscrowUnknown.selector);
        escrow.release(0);
        vm.expectRevert(PQPayGuardEscrow.EscrowUnknown.selector);
        escrow.revokeEscrow(7);
        vm.expectRevert(PQPayGuardEscrow.EscrowUnknown.selector);
        escrow.guardianApprove(3);
    }

    // ---- views -------------------------------------------------------------

    function testReleaseBlockerStrings() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 45);
        assertEq(escrow.releaseBlocker(eid), bytes32("timelock"), "timelock");
        vm.warp(T0 + MED);
        assertEq(escrow.releaseBlocker(eid), bytes32(0), "clear");

        uint256 e2 = _mkEscrow(sid, 95);
        assertEq(escrow.releaseBlocker(e2), bytes32("quarantined"), "quarantined");

        escrow.release(eid);
        assertEq(escrow.releaseBlocker(eid), bytes32("not_funded"), "not funded");
    }

    function testTierOfBoundaries() public {
        assertEq(uint8(escrow.tierOf(0)), uint8(PQPayGuardEscrow.Tier.Low), "0");
        assertEq(uint8(escrow.tierOf(29)), uint8(PQPayGuardEscrow.Tier.Low), "29");
        assertEq(uint8(escrow.tierOf(30)), uint8(PQPayGuardEscrow.Tier.Medium), "30");
        assertEq(uint8(escrow.tierOf(59)), uint8(PQPayGuardEscrow.Tier.Medium), "59");
        assertEq(uint8(escrow.tierOf(60)), uint8(PQPayGuardEscrow.Tier.High), "60");
        assertEq(uint8(escrow.tierOf(84)), uint8(PQPayGuardEscrow.Tier.High), "84");
        assertEq(uint8(escrow.tierOf(85)), uint8(PQPayGuardEscrow.Tier.Critical), "85");
        assertEq(uint8(escrow.tierOf(100)), uint8(PQPayGuardEscrow.Tier.Critical), "100");
        vm.expectRevert(PQPayGuardEscrow.InvalidScore.selector);
        escrow.tierOf(101);
    }

    // ---- events -----------------------------------------------------------

    function testEscrowCreatedEvent() public {
        uint256 sid = _session();
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 45, att, dl);
        vm.expectEmit(true, true, true, true);
        emit PQPayGuardEscrow.EscrowCreated(
            0, sid, payer, recipient, 100_000_000, 45,
            PQPayGuardEscrow.Tier.Medium, uint64(T0 + MED), dl, att, com
        );
        vm.prank(payer);
        escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);
    }

    function testEscrowReleasedEvent() public {
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, 10);
        vm.expectEmit(true, true, false, true);
        emit PQPayGuardEscrow.EscrowReleased(eid, recipient, 100_000_000);
        escrow.release(eid);
    }

    // ---- reentrancy --------------------------------------------------------

    function testReentrancyGuardOnRelease() public {
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

        // arm attack: during release transfer, token tries release again
        evil.setAttack(eid, true, false);
        escrow2.release(eid); // outer succeeds; inner reverts inside guard
        assertEq(evil.reenterAttempts(), 1, "attempt made");
        assertEq(evil.balanceOf(recipient), 100_000, "single payout only");
        assertEq(evil.balanceOf(address(escrow2)), 0, "no double spend");
    }

    function testReentrancyGuardOnCreate() public {
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
        evil.setAttack(0, false, true); // reenter during the transferFrom pull
        vm.prank(payer);
        uint256 eid = escrow2.createEscrow(sid, recipient, 100_000, 10, att, com, dl);
        assertEq(eid, 0, "created");
        assertEq(evil.reenterAttempts(), 1, "reentry attempted and blocked");
        assertEq(evil.balanceOf(address(escrow2)), 100_000, "funded once");
    }

    // ---- fuzz --------------------------------------------------------------

    function _bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (lo > hi) return lo;
        return lo + (x % (hi - lo + 1));
    }

    function testFuzzTierMapping(uint8 score) public {
        if (score > 100) {
            vm.expectRevert(PQPayGuardEscrow.InvalidScore.selector);
            escrow.tierOf(score);
            return;
        }
        uint8 t = uint8(escrow.tierOf(score));
        if (score <= 29) assertEq(t, 0, "low");
        else if (score <= 59) assertEq(t, 1, "medium");
        else if (score <= 84) assertEq(t, 2, "high");
        else assertEq(t, 3, "critical");
    }

    function testFuzzCaps(uint256 maxPerTx, uint256 capTotal, uint256 amount) public {
        maxPerTx = _bound(maxPerTx, 1, 1_000_000_000_000);
        capTotal = _bound(capTotal, maxPerTx, 1_000_000_000_000);
        amount = _bound(amount, 0, 2_000_000_000_000);

        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), guardian, maxPerTx, capTotal, uint64(T0 + EXPIRY_D), MED, HIGH
        );
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, amount, 10, att, dl);
        vm.prank(payer);
        if (amount == 0) {
            vm.expectRevert(PQPayGuardEscrow.InvalidAmount.selector);
            escrow.createEscrow(sid, recipient, amount, 10, att, com, dl);
            return;
        }
        if (amount > maxPerTx) {
            vm.expectRevert(PQPayGuardEscrow.PerTxCapExceeded.selector);
            escrow.createEscrow(sid, recipient, amount, 10, att, com, dl);
            return;
        }
        if (amount > capTotal) {
            vm.expectRevert(PQPayGuardEscrow.CumulativeCapExceeded.selector);
            escrow.createEscrow(sid, recipient, amount, 10, att, com, dl);
            return;
        }
        escrow.createEscrow(sid, recipient, amount, 10, att, com, dl);
        assertEq(escrow.getSession(0).spent, amount, "spent tracked");
    }

    function testFuzzMediumTimelock(uint64 delay, uint64 warpBy) public {
        delay = uint64(_bound(delay, 0, 30 days));
        warpBy = uint64(_bound(warpBy, 0, 60 days));

        vm.prank(payer);
        uint256 sid = escrow.createSession(
            address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + 365 days), delay, delay
        );
        uint64 dl = uint64(T0 + 200 days); // deadline beyond any unlock
        bytes32 att = _att();
        bytes32 com = _commit(sid, recipient, 100_000_000, 45, att, dl);
        vm.prank(payer);
        uint256 eid = escrow.createEscrow(sid, recipient, 100_000_000, 45, att, com, dl);

        vm.warp(T0 + warpBy);
        if (warpBy >= delay) {
            escrow.release(eid);
            assertEq(token.balanceOf(recipient), 100_000_000, "released at or after delay");
        } else {
            vm.expectRevert();
            escrow.release(eid);
        }
    }

    function testFuzzScoreNeverReleasesEarly(uint8 score) public {
        vm.assume(score <= 100);
        vm.assume(score > 29); // medium+ always has some gate
        uint256 sid = _session();
        uint256 eid = _mkEscrow(sid, score);
        if (score <= 84) {
            vm.expectRevert();
            escrow.release(eid);
        } else {
            vm.expectRevert(PQPayGuardEscrow.Quarantined.selector);
            escrow.release(eid);
        }
    }
}
