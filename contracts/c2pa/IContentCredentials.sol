// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vitruveo Content Credentials (precompile at 0x00000000000000000000000000000000000000CA)
/// @notice Verifies C2PA manifest stores on chain against an on-chain trust list
/// and records the result for files in the file storage precompile (0x...F1).
///
/// Flow for an artwork with embedded Content Credentials (JPEG or PNG):
///   1. Upload it with IFileStore.beginWithCredential, passing the byte range of
///      the embedded manifest store as the exclusion. The file store computes the
///      content hash (file without that range) during upload.
///   2. Send verify(fileHash, manifestStore) as a direct transaction (calldata
///      costs 2 gas per byte). It checks every claim signature, assertion hash and
///      ingredient link, that the active signer chains to a trust anchor with all
///      certificates valid and unrevoked at the block time, and that the manifest's
///      data hash equals the file's content hash. The result is stored.
///   3. Contracts read provenance(fileHash) / lineage(fileHash).
///
/// Supported: COSE ES256/384/512, PS256/384/512, EdDSA; claim v1 and v2;
/// c2pa.hash.data bindings with SHA-256. Not supported yet: hash.bmff (MP4/HEIC)
/// and timestamp-authority tokens (certificates are checked at block time).
///
/// Trust list admin: initially a 2-of-2 native multisig wallet created by
/// setupAdmin() (anyone can call it once); owners are fixed in the node.
/// Admin calls go through IMultisig.execute with this precompile as target.
/// Fingerprints are SHA-256 of the DER certificate.
interface IContentCredentials {
    event AdminChanged(address indexed admin);
    event AnchorAdded(bytes32 indexed fingerprint);
    event AnchorRemoved(bytes32 indexed fingerprint);
    event Revoked(bytes32 indexed fingerprint, uint256 effectiveTime);
    event Unrevoked(bytes32 indexed fingerprint);
    event ProvenanceVerified(bytes32 indexed fileHash, bytes32 indexed signer, bytes32 anchor);

    // Admin
    function setupAdmin() external returns (address wallet);
    function admin() external view returns (address);
    function setAdmin(address newAdmin) external returns (bool);
    function addAnchor(bytes calldata derCertificate) external returns (bytes32 fingerprint);
    function removeAnchor(bytes32 fingerprint) external returns (bool);
    /// Revokes any certificate in a chain from effectiveTime (unix seconds).
    function revoke(bytes32 fingerprint, uint256 effectiveTime) external returns (bool);
    function unrevoke(bytes32 fingerprint) external returns (bool);
    function isAnchor(bytes32 fingerprint) external view returns (bool);
    function revokedAt(bytes32 fingerprint) external view returns (bool revoked, uint256 effectiveTime);

    // Verification
    function verify(bytes32 fileHash, bytes calldata manifestStore)
        external
        returns (bytes32 signer, bytes32 anchor, string memory signerName, string memory claimGenerator, uint256 manifests);

    /// Verifies a manifest store without a stored file and without recording.
    function check(bytes calldata manifestStore)
        external
        view
        returns (
            bytes32 signer,
            bytes32 anchor,
            string memory signerName,
            string memory claimGenerator,
            uint256 manifests,
            bytes32 dataHash,
            uint256[] memory exclusionStart,
            uint256[] memory exclusionLength
        );

    /// valid is false if a certificate on the recorded path was later revoked
    /// effective at or before the verification time, or the anchor was removed.
    function provenance(bytes32 fileHash)
        external
        view
        returns (
            bool valid,
            bytes32 signer,
            bytes32 anchor,
            string memory signerName,
            string memory claimGenerator,
            uint256 manifests,
            uint256 blockNumber,
            address verifiedBy
        );

    /// Signer fingerprint of each manifest in the verified store, oldest first.
    function lineage(bytes32 fileHash) external view returns (bytes32[] memory signers);
}
