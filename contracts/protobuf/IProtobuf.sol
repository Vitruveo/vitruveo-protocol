// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vitruveo protobuf precompile (0x00000000000000000000000000000000000000B0)
/// @notice Schema-less protobuf wire codec plus cheap on-chain message storage.
/// @dev Call through the Protobuf library (low-level calls). Calling this
/// interface directly fails for functions without return values, because
/// Solidity checks that the target has code and the precompile has none.
///
/// Paths are field numbers from the outer message inward; every element but the
/// last must be an embedded message. The last occurrence of a field is the one
/// read or replaced. Values: varint/fixed are 32-byte big-endian words; bytes,
/// strings and embedded messages are raw bytes.
/// Wire types: 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32.
///
/// Storage is namespaced by msg.sender: a contract can only write its own
/// messages, and anyone can read any message. Writes revert in STATICCALL.
interface IProtobuf {
    // Codec
    function decode(bytes calldata data)
        external view returns (uint256[] memory fieldNumbers, uint256[] memory wireTypes, bytes[] memory values);
    function encode(uint256[] calldata fieldNumbers, uint256[] calldata wireTypes, bytes[] calldata values)
        external view returns (bytes memory data);
    function decodePacked(bytes calldata data, uint256 wireType) external view returns (uint256[] memory values);
    function encodePacked(uint256[] calldata values, uint256 wireType) external view returns (bytes memory data);

    // Field access on a message in memory
    function read(bytes calldata data, uint256[] calldata path)
        external view returns (bool found, uint256 wireType, bytes memory value);
    function readAll(bytes calldata data, uint256[] calldata path)
        external view returns (uint256[] memory wireTypes, bytes[] memory values);
    function write(bytes calldata data, uint256[] calldata path, uint256 wireType, bytes calldata value)
        external view returns (bytes memory);
    function append(bytes calldata data, uint256[] calldata path, uint256 wireType, bytes calldata value)
        external view returns (bytes memory);
    function clear(bytes calldata data, uint256[] calldata path) external view returns (bytes memory);

    // Storage
    function store(bytes32 key, bytes calldata data) external;
    function load(address owner, bytes32 key) external view returns (bytes memory data);
    function remove(bytes32 key) external;
    function loadField(address owner, bytes32 key, uint256[] calldata path)
        external view returns (bool found, uint256 wireType, bytes memory value);
    function loadAll(address owner, bytes32 key, uint256[] calldata path)
        external view returns (uint256[] memory wireTypes, bytes[] memory values);
    function storeField(bytes32 key, uint256[] calldata path, uint256 wireType, bytes calldata value) external;
    function appendField(bytes32 key, uint256[] calldata path, uint256 wireType, bytes calldata value) external;
    function clearField(bytes32 key, uint256[] calldata path) external;
}
