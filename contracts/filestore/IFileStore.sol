// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vitruveo file storage (precompile at 0x00000000000000000000000000000000000000F1)
/// @notice Stores files up to 10 MB on chain, addressed by SHA-256 and immutable
/// once finalized. File bytes live in the calldata of upload transactions (block
/// bodies, kept by every node); state holds only owner, size, content type and
/// chunk locations.
///
/// Upload from an EOA, in this order (consecutive nonces can be sent at once):
///   1. begin(sha256, size, contentType)
///   2. upload(sha256, i, chunk) for i = 0, 1, 2 ... with chunks of up to 512 KB
///   3. finalize(sha256)  - checks the SHA-256 of all chunks
/// upload() must be a transaction sent directly to this address (not a call from
/// a contract); such transactions pay 2 gas per calldata byte instead of 16.
/// Calling begin() again restarts an unfinished upload.
///
/// Served by nodes at  https://<rpc host>/file/<sha256 hex>[.ext]  with the stored
/// content type, CORS, range requests and immutable caching.
interface IFileStore {
    event FileStored(bytes32 indexed sha256Hash, address indexed owner, uint256 size, string contentType);

    function begin(bytes32 sha256Hash, uint256 size, string calldata contentType) external returns (bool);

    /// Same as begin() for a file with embedded Content Credentials (C2PA). The
    /// excluded byte ranges (the embedded manifest store, sorted) are left out of
    /// a second hash, the content hash, which the C2PA precompile (0x...CA)
    /// compares with the manifest's c2pa.hash.data assertion.
    function beginWithCredential(
        bytes32 sha256Hash,
        uint256 size,
        string calldata contentType,
        uint256[] calldata exclusionStart,
        uint256[] calldata exclusionLength
    ) external returns (bool);
    function upload(bytes32 sha256Hash, uint256 index, bytes calldata chunk) external returns (bool);
    function finalize(bytes32 sha256Hash) external returns (bool);

    function exists(bytes32 sha256Hash) external view returns (bool);

    function info(bytes32 sha256Hash)
        external
        view
        returns (address owner, uint256 size, string memory contentType, uint256 chunks, uint256 blockNumber);

    /// status: 0 none, 1 uploading, 2 finalized
    function session(address owner, bytes32 sha256Hash)
        external
        view
        returns (uint256 status, uint256 size, uint256 received, uint256 chunks);

    /// Content hash and exclusions of a file uploaded with beginWithCredential.
    function credentialInfo(bytes32 sha256Hash)
        external
        view
        returns (bytes32 contentHash, uint256[] memory exclusionStart, uint256[] memory exclusionLength);

    /// Where chunk `index` of a finalized file is: read it with
    /// eth_getTransactionByBlockNumberAndIndex and ABI-decode upload() calldata.
    function chunkLocation(bytes32 sha256Hash, uint256 index)
        external
        view
        returns (uint256 blockNumber, uint256 txIndex);
}
