// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vitruveo native multisig (precompile at 0x00000000000000000000000000000000000000AC)
/// @notice Keyless wallets controlled by a threshold of owners. Owners are
/// addresses (EOAs or contracts) or P-256 passkeys. A wallet holds VTRU, tokens
/// and NFTs like any address, and executes batches of calls all-or-nothing.
///
/// Approvals for execute() are counted from distinct owners:
///   - signatures: EOA = 0x01 | r | s | v over operationHash (EIP-712, see below)
///                 passkey = 0x02 | abi.encode(x, y, authenticatorData, clientDataJSON, r, s)
///                 where the WebAuthn challenge is operationHash (base64url)
///     Both forms must be low-S (s <= N/2 of the respective curve; secp256k1
///     for EOA, P-256 for passkey). High-S signatures are rejected, so passkey
///     signers must normalize s to N - s when s > N/2.
///   - prior on-chain approve() calls by address owners
///   - msg.sender of execute(), if it is an address owner
///
/// EIP-712 (eth_signTypedData_v4):
///   domain  { name: "Vitruveo Multisig", version: "1", chainId, verifyingContract: wallet }
///   Execute(Call[] calls,uint256 nonce)  Call(address to,uint256 value,bytes data)
///
/// Owner and threshold changes are calls from the wallet to this precompile
/// (addOwner/addPasskey/removeOwner/setThreshold) inside execute().
/// Owner ids: address owner = bytes32(uint256(uint160(owner))); passkey = keccak256(abi.encode(x, y)).
/// Send VTRU to the wallet address directly, not with a call to this precompile.
interface IMultisig {
    event WalletCreated(address indexed wallet, address indexed creator);
    event Approved(address indexed wallet, bytes32 indexed opHash, bytes32 ownerId);
    event Executed(address indexed wallet, bytes32 indexed opHash, uint256 nonce);
    event OwnerAdded(address indexed wallet, bytes32 indexed ownerId);
    event OwnerRemoved(address indexed wallet, bytes32 indexed ownerId);
    event ThresholdChanged(address indexed wallet, uint256 indexed threshold);

    function walletAddress(address creator, bytes32 salt) external view returns (address wallet);

    function create(
        address[] calldata owners,
        uint256[] calldata passkeyX,
        uint256[] calldata passkeyY,
        uint256 threshold,
        bytes32 salt
    ) external returns (address wallet);

    function operationHash(
        address wallet,
        address[] calldata to,
        uint256[] calldata value,
        bytes[] calldata data,
        uint256 nonce
    ) external view returns (bytes32);

    function execute(
        address wallet,
        address[] calldata to,
        uint256[] calldata value,
        bytes[] calldata data,
        bytes[] calldata signatures
    ) external returns (bytes[] memory results);

    function approve(address wallet, bytes32 opHash) external returns (bool);

    function info(address wallet)
        external
        view
        returns (
            address[] memory owners,
            uint256[] memory passkeyX,
            uint256[] memory passkeyY,
            uint256 threshold,
            uint256 nonce
        );

    function approvedBy(address wallet, bytes32 opHash) external view returns (bytes32[] memory ownerIds);

    // Callable only by the wallet itself (as a call inside execute)
    function addOwner(address owner) external returns (bool);
    function addPasskey(uint256 x, uint256 y) external returns (bool);
    function removeOwner(bytes32 ownerId) external returns (bool);
    function setThreshold(uint256 threshold) external returns (bool);
}
