// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestBase} from "./TestBase.sol";
import {PQPayGuardEscrow} from "../contracts/PQPayGuardEscrow.sol";
import {MockTUSD8} from "../contracts/MockTUSD8.sol";

/// @dev Emergency batch rescue and view parity hardening.
contract PQPayGuardEscrowBatchTest is TestBase {
    MockTUSD8 internal token;
    PQPayGuardEscrow internal escrow;
    address internal payer = address(0xA11CE);
    address internal guardian = address(0xCAAD);
    address internal recipient = address(0xDEAD);
    address internal stranger = address(0xF00D);
    uint64 internal constant T0 = 1_760_000_000;

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
        return escrow.createSession(address(0), guardian, 500_000_000, 2_000_000_000, uint64(T0 + 7 days), 900, 3600);
    }

    function _mk(uint256 sid, uint8 score) internal returns (uint256) {
        uint64 dl = uint64(T0 + 1 days);
        bytes32 att = keccak256("batch-att");
        bytes32 com = escrow.computeCommitment(sid, payer, recipient, 100_000_000, score, att, dl);
        vm.prank(payer);
        return escrow.createEscrow(sid, recipient, 100_000_000, score, att, com, dl);
    }

    function testBatchRevokeReturnsCombinedAmount() public {
        uint256 sid = _session();
        uint256 a = _mk(sid, 10);
        uint256 b = _mk(sid, 45);
        uint256 c = _mk(sid, 90);
        uint256 before = token.balanceOf(payer);
        uint256[] memory ids = new uint256[](3);
        ids[0] = a; ids[1] = b; ids[2] = c;
        vm.prank(payer);
        escrow.revokeEscrows(ids);
        assertEq(token.balanceOf(payer), before + 300_000_000, "combined amount returned");
        assertEq(token.balanceOf(address(escrow)), 0, "escrow empty");
        assertEq(uint256(escrow.getEscrow(a).status), uint256(PQPayGuardEscrow.Status.Revoked), "a revoked");
        assertEq(uint256(escrow.getEscrow(c).status), uint256(PQPayGuardEscrow.Status.Revoked), "c revoked");
    }

    function testBatchEventsPreserveAuditTrail() public {
        uint256 sid = _session();
        uint256 a = _mk(sid, 10);
        uint256 b = _mk(sid, 20);
        uint256[] memory ids = new uint256[](2);
        ids[0] = a; ids[1] = b;
        vm.expectEmit(true, true, false, true);
        emit PQPayGuardEscrow.EscrowRevoked(a, payer, 100_000_000);
        vm.expectEmit(true, true, false, true);
        emit PQPayGuardEscrow.EscrowRevoked(b, payer, 100_000_000);
        vm.expectEmit(true, false, false, true);
        emit PQPayGuardEscrow.EscrowsBatchRevoked(payer, 2, 200_000_000);
        vm.prank(payer);
        escrow.revokeEscrows(ids);
    }

    function testBatchEmptyReverts() public {
        uint256[] memory ids = new uint256[](0);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidBatchSize.selector);
        escrow.revokeEscrows(ids);
    }

    function testBatchOversizeReverts() public {
        uint256[] memory ids = new uint256[](65);
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.InvalidBatchSize.selector);
        escrow.revokeEscrows(ids);
    }

    function testBatchDuplicateIdReverts() public {
        uint256 sid = _session();
        uint256 a = _mk(sid, 10);
        uint256[] memory ids = new uint256[](2);
        ids[0] = a; ids[1] = a;
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.DuplicateEscrowId.selector);
        escrow.revokeEscrows(ids);
    }

    function testBatchUnknownIdReverts() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = 99;
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.EscrowUnknown.selector);
        escrow.revokeEscrows(ids);
    }

    function testBatchForeignEscrowRevertsWithoutMovingFunds() public {
        uint256 sid = _session();
        uint256 a = _mk(sid, 10);
        uint256[] memory ids = new uint256[](1);
        ids[0] = a;
        uint256 before = token.balanceOf(address(escrow));
        vm.prank(stranger);
        vm.expectRevert(PQPayGuardEscrow.NotPayer.selector);
        escrow.revokeEscrows(ids);
        assertEq(token.balanceOf(address(escrow)), before, "funds unmoved");
        assertEq(uint256(escrow.getEscrow(a).status), uint256(PQPayGuardEscrow.Status.Funded), "still funded");
    }

    function testBatchNonFundedReverts() public {
        uint256 sid = _session();
        uint256 a = _mk(sid, 10);
        uint256 b = _mk(sid, 10);
        vm.prank(payer);
        escrow.revokeEscrow(a);
        uint256[] memory ids = new uint256[](2);
        ids[0] = b; ids[1] = a;
        vm.prank(payer);
        vm.expectRevert(PQPayGuardEscrow.EscrowNotFunded.selector);
        escrow.revokeEscrows(ids);
    }

    function testReleaseBlockerUnknownEscrowReverts() public {
        vm.expectRevert(PQPayGuardEscrow.EscrowUnknown.selector);
        escrow.releaseBlocker(12345);
    }

    function testMaxBatchConstant() public view {
        assertEq(escrow.MAX_BATCH_REVOKE(), 64, "batch cap");
    }
}
