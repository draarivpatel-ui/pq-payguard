// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @dev Minimal forge cheatcode surface (the parts this suite needs) so the
/// repo has zero lib dependencies: no forge-std download is required to run
/// `forge test`.
interface Vm {
    function warp(uint256 newTimestamp) external;
    function prank(address msgSender) external;
    function startPrank(address msgSender) external;
    function stopPrank() external;
    function expectRevert() external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData) external;
    function assume(bool condition) external;
    function bound(uint256 x, uint256 min, uint256 max) external returns (uint256);
    function targetContract(address newTargetedContract) external;
    function chainId(uint256 newChainId) external;
}

contract TestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool v, string memory m) internal pure {
        require(v, m);
    }

    function assertFalse(bool v, string memory m) internal pure {
        require(!v, m);
    }

    function assertEq(uint256 a, uint256 b, string memory m) internal pure {
        require(a == b, string.concat(m, " uint ", _u2s(a), " != ", _u2s(b)));
    }

    function assertEq(int256 a, int256 b, string memory m) internal pure {
        require(a == b, m);
    }

    function assertEq(address a, address b, string memory m) internal pure {
        require(a == b, m);
    }

    function assertEq(bytes32 a, bytes32 b, string memory m) internal pure {
        require(a == b, m);
    }

    function assertEq(string memory a, string memory b, string memory m) internal pure {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), m);
    }

    function fail(string memory m) internal pure {
        require(false, m);
    }

    function _u2s(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 digits;
        uint256 t = v;
        while (t != 0) {
            digits++;
            t /= 10;
        }
        bytes memory b = new bytes(digits);
        while (v != 0) {
            digits -= 1;
            b[digits] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }
        return string(b);
    }
}
