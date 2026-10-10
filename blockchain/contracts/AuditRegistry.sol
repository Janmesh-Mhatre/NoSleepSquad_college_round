// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Incognito Audit Registry
 * @notice Stores public, privacy-preserving cryptographic batch commitments (Merkle roots).
 * @dev STRICT PRIVACY RULES:
 * - NO report text or ciphertext is stored or emitted.
 * - NO student / member identity or credential is stored or emitted.
 * - NO IP addresses or network metadata are stored or emitted.
 * - Only aggregate batch commitments (bytes32 Merkle roots) are recorded.
 */
contract AuditRegistry {
    struct BatchCommitment {
        bytes32 merkleRoot;
        uint256 recordCount;
        uint256 timestamp;
        address publisher;
        bool exists;
    }

    address public owner;
    mapping(address => bool) public authorizedPublishers;
    mapping(string => BatchCommitment) private batches;
    string[] private batchIds;

    event BatchPublished(
        string indexed batchId,
        bytes32 indexed merkleRoot,
        uint256 recordCount,
        uint256 timestamp,
        address publisher
    );

    event PublisherUpdated(address indexed publisher, bool authorized);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "AuditRegistry: caller is not the owner");
        _;
    }

    modifier onlyPublisher() {
        require(
            authorizedPublishers[msg.sender] || msg.sender == owner,
            "AuditRegistry: caller is not an authorized publisher"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedPublishers[msg.sender] = true;
    }

    /**
     * @notice Authorize or revoke an institutional publishing address.
     */
    function setPublisher(address publisher, bool authorized) external onlyOwner {
        require(publisher != address(0), "AuditRegistry: zero address");
        authorizedPublishers[publisher] = authorized;
        emit PublisherUpdated(publisher, authorized);
    }

    /**
     * @notice Transfers contract ownership to a new address.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "AuditRegistry: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        authorizedPublishers[newOwner] = true;
    }

    /**
     * @notice Publishes a minimal cryptographic Merkle root for an audit batch.
     */
    function publishBatch(
        string calldata batchId,
        bytes32 merkleRoot,
        uint256 recordCount
    ) external onlyPublisher {
        require(bytes(batchId).length > 0, "AuditRegistry: empty batch ID");
        require(merkleRoot != bytes32(0), "AuditRegistry: zero Merkle root");
        require(!batches[batchId].exists, "AuditRegistry: batch already published");
        require(recordCount > 0, "AuditRegistry: record count must be greater than zero");

        batches[batchId] = BatchCommitment({
            merkleRoot: merkleRoot,
            recordCount: recordCount,
            timestamp: block.timestamp,
            publisher: msg.sender,
            exists: true
        });

        batchIds.push(batchId);

        emit BatchPublished(batchId, merkleRoot, recordCount, block.timestamp, msg.sender);
    }

    /**
     * @notice Verifies whether a given Merkle root matches the recorded commitment on-chain.
     */
    function verifyBatch(
        string calldata batchId,
        bytes32 expectedRoot
    )
        external
        view
        returns (
            bool matches,
            bytes32 onChainRoot,
            uint256 recordCount,
            uint256 timestamp,
            address publisher
        )
    {
        BatchCommitment memory batch = batches[batchId];
        if (!batch.exists) {
            return (false, bytes32(0), 0, 0, address(0));
        }

        return (
            batch.merkleRoot == expectedRoot,
            batch.merkleRoot,
            batch.recordCount,
            batch.timestamp,
            batch.publisher
        );
    }

    /**
     * @notice Retrieves total number of published batches.
     */
    function getBatchCount() external view returns (uint256) {
        return batchIds.length;
    }

    /**
     * @notice Returns batch ID by array index.
     */
    function getBatchIdByIndex(uint256 index) external view returns (string memory) {
        require(index < batchIds.length, "AuditRegistry: index out of bounds");
        return batchIds[index];
    }
}
