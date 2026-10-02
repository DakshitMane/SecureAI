// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuditGate {
    address public owner;
    uint256 public constant HIGH_RISK_THRESHOLD = 80;

    struct AuditRecord {
        bytes32 contractHash;
        uint256 riskScore;
        bool isFlagged;
        uint256 timestamp;
    }

    mapping(bytes32 => AuditRecord) public auditRegistry;

    event AuditCommitted(
        bytes32 indexed contractHash,
        uint256 riskScore,
        bool isFlagged,
        uint256 timestamp
    );

    constructor() {
        owner = msg.sender;
    }

    function commitAudit(bytes32 _contractHash, uint256 _riskScore) external returns (bool) {
        require(_riskScore <= 100, "Score must be between 0 and 100");

        bool flagged = _riskScore >= HIGH_RISK_THRESHOLD;

        auditRegistry[_contractHash] = AuditRecord({
            contractHash: _contractHash,
            riskScore: _riskScore,
            isFlagged: flagged,
            timestamp: block.timestamp
        });

        emit AuditCommitted(_contractHash, _riskScore, flagged, block.timestamp);
        return flagged;
    }

    function getAudit(bytes32 _contractHash) external view returns (uint256 riskScore, bool isFlagged, uint256 timestamp) {
        AuditRecord memory record = auditRegistry[_contractHash];
        require(record.timestamp > 0, "Audit record not found");
        return (record.riskScore, record.isFlagged, record.timestamp);
    }
}