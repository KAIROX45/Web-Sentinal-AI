// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatVerification
 * @dev Immutable on-chain registry for cryptographic threat intelligence fingerprints.
 * Preserves report integrity without exposing sensitive personal data or raw investigation payloads.
 */
contract ThreatVerification {
    address public immutable owner;

    enum RiskLevel {
        LOW,
        SUSPICIOUS,
        HIGH,
        CONFIRMED_MALICIOUS
    }

    struct ThreatRecord {
        bytes32 reportHash;
        address reporter;
        string threatType;     // "url", "ip", "message", "tls"
        RiskLevel riskLevel;
        uint256 timestamp;
        string metadataUri;    // Optional IPFS or decentralized pointer
    }

    // Mapping from canonical SHA-256 report hash to verification record
    mapping(bytes32 => ThreatRecord) private _threatRecords;
    bytes32[] private _recordedHashes;

    event ThreatReportRecorded(
        bytes32 indexed reportHash,
        address indexed reporter,
        string threatType,
        RiskLevel riskLevel,
        uint256 timestamp
    );

    error ReportAlreadyRecorded(bytes32 reportHash);
    error InvalidReportHash();
    error ReportNotFound(bytes32 reportHash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the contract owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Records the cryptographic fingerprint of a verified threat investigation.
     * @param reportHash The 32-byte SHA-256 hash of canonicalized threat report JSON.
     * @param threatType Type of investigated indicator (url, ip, message, tls).
     * @param riskLevel Classified severity level (0=LOW, 1=SUSPICIOUS, 2=HIGH, 3=CONFIRMED_MALICIOUS).
     * @param metadataUri Pointer to decentralized metadata or report summary.
     */
    function recordThreatReport(
        bytes32 reportHash,
        string calldata threatType,
        RiskLevel riskLevel,
        string calldata metadataUri
    ) external {
        if (reportHash == bytes32(0)) revert InvalidReportHash();
        if (_threatRecords[reportHash].timestamp != 0) revert ReportAlreadyRecorded(reportHash);

        ThreatRecord memory record = ThreatRecord({
            reportHash: reportHash,
            reporter: msg.sender,
            threatType: threatType,
            riskLevel: riskLevel,
            timestamp: block.timestamp,
            metadataUri: metadataUri
        });

        _threatRecords[reportHash] = record;
        _recordedHashes.push(reportHash);

        emit ThreatReportRecorded(
            reportHash,
            msg.sender,
            threatType,
            riskLevel,
            block.timestamp
        );
    }

    /**
     * @notice Verifies whether a threat report fingerprint exists on-chain and returns proof metadata.
     * @param reportHash SHA-256 fingerprint to verify.
     */
    function verifyThreatReport(bytes32 reportHash)
        external
        view
        returns (
            bool exists,
            bytes32 hash,
            address reporter,
            string memory threatType,
            RiskLevel riskLevel,
            uint256 timestamp,
            string memory metadataUri
        )
    {
        ThreatRecord memory record = _threatRecords[reportHash];
        if (record.timestamp == 0) {
            return (false, bytes32(0), address(0), "", RiskLevel.LOW, 0, "");
        }
        return (
            true,
            record.reportHash,
            record.reporter,
            record.threatType,
            record.riskLevel,
            record.timestamp,
            record.metadataUri
        );
    }

    /**
     * @notice Returns total number of registered threat fingerprints.
     */
    function getTotalReports() external view returns (uint256) {
        return _recordedHashes.length;
    }

    /**
     * @notice Retrieves recorded hash by index for audit pagination.
     */
    function getReportHashAtIndex(uint256 index) external view returns (bytes32) {
        require(index < _recordedHashes.length, "Index out of bounds");
        return _recordedHashes[index];
    }
}

