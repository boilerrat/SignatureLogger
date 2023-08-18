// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureLogger is AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    mapping(bytes32 => bool) public isSignatureLogged;
    mapping(address => uint256) public lastButtonPressTime; // Mapping to track the last press time for each address

    uint256 public buttonPressCounter = 0;
    uint256 public constant RATE_LIMIT = 2 minutes; // Rate limit of 2 minutes

    event SignatureLogged(bytes32 messageHash, address signer, string message, uint256 buttonPress);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(SIGNER_ROLE, msg.sender);
    }

    function logSignature(bytes32 messageHash, bytes memory signature, string memory message) public {
        require(hasRole(SIGNER_ROLE, msg.sender), "Caller is not a signer");
        require(block.timestamp >= lastButtonPressTime[msg.sender] + RATE_LIMIT, "Rate limit exceeded"); // Check against rate limit

        address signer = messageHash.recover(signature);
        require(signer == msg.sender, "Invalid signature");
        require(!isSignatureLogged[messageHash], "Signature already logged");

        buttonPressCounter++;
        isSignatureLogged[messageHash] = true;
        lastButtonPressTime[msg.sender] = block.timestamp; // Update the last press time for the caller

        emit SignatureLogged(messageHash, signer, message, buttonPressCounter);
    }

    function grantSignerRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(SIGNER_ROLE, account);
    }

    function revokeSignerRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(SIGNER_ROLE, account);
    }
}