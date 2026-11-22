// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../PQPayGuardEscrow.sol";

interface IEscrowReentry {
    function release(uint256 escrowId) external;
    function createEscrow(
        uint256 sessionId,
        address recipient,
        uint256 amount,
        uint8 riskScore,
        bytes32 attestationHash,
        bytes32 commitmentHash,
        uint64 deadline
    ) external returns (uint256);
}

/// @title ReentrantToken
/// @notice Malicious ERC-20 mock that attempts to reenter release() during the
/// outbound transfer and createEscrow() during the inbound transfer. Used to
/// prove the escrow reentrancy guard and checks-effects-interactions ordering
/// in local EVM tests. Test chains only.
contract ReentrantToken {
    string public constant name = "Reentrant Mock";
    string public constant symbol = "RNT";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public escrow;
    uint256 public attackEscrowId;
    bool public attackOnTransfer;
    bool public attackOnTransferFrom;
    uint256 public reenterAttempts;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    function setEscrow(address escrow_) external {
        escrow = escrow_;
    }

    function setAttack(uint256 escrowId, bool onTransfer, bool onTransferFrom) external {
        attackEscrowId = escrowId;
        attackOnTransfer = onTransfer;
        attackOnTransferFrom = onTransferFrom;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        if (attackOnTransfer && to != escrow && escrow != address(0)) {
            attackOnTransfer = false;
            reenterAttempts += 1;
            // This must fail inside the escrow reentrancy guard; we swallow the
            // revert so the outer call can report the attempt count.
            try IEscrowReentry(escrow).release(attackEscrowId) {} catch {}
        }
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        if (attackOnTransferFrom && escrow != address(0)) {
            attackOnTransferFrom = false;
            reenterAttempts += 1;
            try IEscrowReentry(escrow).release(attackEscrowId) {} catch {}
        }
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero to");
        require(balanceOf[from] >= amount, "balance");
        unchecked {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }
}
