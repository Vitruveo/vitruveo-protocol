// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IProtobuf} from "./IProtobuf.sol";

/// @title Protobuf
/// @notice Typed helpers over the Vitruveo protobuf precompile.
///
/// Stored messages (namespaced by the calling contract):
///
///     using Protobuf for bytes32;
///     bytes32 key = keccak256(abi.encode(tokenId));
///     key.setString(Protobuf.path(1), "Sunset");            // name = 1
///     key.setUint(Protobuf.path(2, 1), 1920);               // dims.width = 2.1
///     key.addString(Protobuf.path(3), "landscape");         // repeated tags = 3
///     string memory name = Protobuf.getString(address(this), key, Protobuf.path(1));
///
/// Messages in memory:
///
///     bytes memory m = Protobuf.setString(new bytes(0), Protobuf.path(1), "Sunset");
///     m = Protobuf.setUint(m, Protobuf.path(2, 1), 1920);
///     uint256 w = Protobuf.getUint(m, Protobuf.path(2, 1));
///
/// Start a new in-memory message from new bytes(0) (a bare "" literal is
/// ambiguous between the bytes32 and bytes overloads).
///
/// Missing fields read as protobuf defaults (0, false, ""); use has() to tell
/// "absent" from "default".
library Protobuf {
    address internal constant PRECOMPILE = 0x00000000000000000000000000000000000000B0;

    uint256 internal constant VARINT = 0;
    uint256 internal constant FIXED64 = 1;
    uint256 internal constant BYTES = 2;
    uint256 internal constant FIXED32 = 5;

    error ProtobufCallFailed();

    // ------------------------------------------------------------------
    // Paths
    // ------------------------------------------------------------------

    function path(uint256 a) internal pure returns (uint256[] memory p) {
        p = new uint256[](1);
        p[0] = a;
    }

    function path(uint256 a, uint256 b) internal pure returns (uint256[] memory p) {
        p = new uint256[](2);
        (p[0], p[1]) = (a, b);
    }

    function path(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory p) {
        p = new uint256[](3);
        (p[0], p[1], p[2]) = (a, b, c);
    }

    function path(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256[] memory p) {
        p = new uint256[](4);
        (p[0], p[1], p[2], p[3]) = (a, b, c, d);
    }

    // ------------------------------------------------------------------
    // Scalar conversions
    // ------------------------------------------------------------------

    /// @dev int32/int64 fields: negative values are 64-bit two's complement.
    function toInt(uint256 raw) internal pure returns (int64) {
        return int64(uint64(raw));
    }

    function fromInt(int64 v) internal pure returns (uint256) {
        return uint256(uint64(v));
    }

    /// @dev sint32/sint64 fields use zigzag encoding.
    function toSint(uint256 raw) internal pure returns (int64) {
        uint64 n = uint64(raw);
        return int64(n >> 1) ^ -int64(n & 1);
    }

    function fromSint(int64 v) internal pure returns (uint256) {
        return uint256(uint64((v << 1) ^ (v >> 63)));
    }

    // ------------------------------------------------------------------
    // Stored messages: read (any owner)
    // ------------------------------------------------------------------

    function load(address owner, bytes32 key) internal view returns (bytes memory) {
        return abi.decode(_view(abi.encodeCall(IProtobuf.load, (owner, key))), (bytes));
    }

    function get(address owner, bytes32 key, uint256[] memory p)
        internal view returns (bool found, uint256 wireType, bytes memory value)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.loadField, (owner, key, p))), (bool, uint256, bytes));
    }

    function getAll(address owner, bytes32 key, uint256[] memory p)
        internal view returns (uint256[] memory wireTypes, bytes[] memory values)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.loadAll, (owner, key, p))), (uint256[], bytes[]));
    }

    function has(address owner, bytes32 key, uint256[] memory p) internal view returns (bool found) {
        (found,,) = get(owner, key, p);
    }

    function getUint(address owner, bytes32 key, uint256[] memory p) internal view returns (uint256) {
        (,, bytes memory v) = get(owner, key, p);
        return _word(v);
    }

    function getInt(address owner, bytes32 key, uint256[] memory p) internal view returns (int64) {
        return toInt(getUint(owner, key, p));
    }

    function getSint(address owner, bytes32 key, uint256[] memory p) internal view returns (int64) {
        return toSint(getUint(owner, key, p));
    }

    function getBool(address owner, bytes32 key, uint256[] memory p) internal view returns (bool) {
        return getUint(owner, key, p) != 0;
    }

    function getBytes(address owner, bytes32 key, uint256[] memory p) internal view returns (bytes memory v) {
        (,, v) = get(owner, key, p);
    }

    function getString(address owner, bytes32 key, uint256[] memory p) internal view returns (string memory) {
        return string(getBytes(owner, key, p));
    }

    /// @notice Repeated numeric field, packed or unpacked.
    function getUints(address owner, bytes32 key, uint256[] memory p) internal view returns (uint256[] memory) {
        (uint256[] memory types, bytes[] memory values) = getAll(owner, key, p);
        return _uints(types, values);
    }

    function getStrings(address owner, bytes32 key, uint256[] memory p) internal view returns (string[] memory out) {
        (, bytes[] memory values) = getAll(owner, key, p);
        out = new string[](values.length);
        for (uint256 i; i < values.length; ++i) out[i] = string(values[i]);
    }

    // ------------------------------------------------------------------
    // Stored messages: write (caller's own namespace)
    // ------------------------------------------------------------------

    function save(bytes32 key, bytes memory message) internal {
        _write(abi.encodeCall(IProtobuf.store, (key, message)));
    }

    function remove(bytes32 key) internal {
        _write(abi.encodeCall(IProtobuf.remove, (key)));
    }

    function set(bytes32 key, uint256[] memory p, uint256 wireType, bytes memory value) internal {
        _write(abi.encodeCall(IProtobuf.storeField, (key, p, wireType, value)));
    }

    function add(bytes32 key, uint256[] memory p, uint256 wireType, bytes memory value) internal {
        _write(abi.encodeCall(IProtobuf.appendField, (key, p, wireType, value)));
    }

    function clear(bytes32 key, uint256[] memory p) internal {
        _write(abi.encodeCall(IProtobuf.clearField, (key, p)));
    }

    function setUint(bytes32 key, uint256[] memory p, uint256 v) internal {
        set(key, p, VARINT, abi.encode(v));
    }

    function setInt(bytes32 key, uint256[] memory p, int64 v) internal {
        set(key, p, VARINT, abi.encode(fromInt(v)));
    }

    function setSint(bytes32 key, uint256[] memory p, int64 v) internal {
        set(key, p, VARINT, abi.encode(fromSint(v)));
    }

    function setBool(bytes32 key, uint256[] memory p, bool v) internal {
        set(key, p, VARINT, abi.encode(v ? 1 : 0));
    }

    function setBytes(bytes32 key, uint256[] memory p, bytes memory v) internal {
        set(key, p, BYTES, v);
    }

    function setString(bytes32 key, uint256[] memory p, string memory v) internal {
        set(key, p, BYTES, bytes(v));
    }

    function addUint(bytes32 key, uint256[] memory p, uint256 v) internal {
        add(key, p, VARINT, abi.encode(v));
    }

    function addBytes(bytes32 key, uint256[] memory p, bytes memory v) internal {
        add(key, p, BYTES, v);
    }

    function addString(bytes32 key, uint256[] memory p, string memory v) internal {
        add(key, p, BYTES, bytes(v));
    }

    // ------------------------------------------------------------------
    // Messages in memory
    // ------------------------------------------------------------------

    function get(bytes memory message, uint256[] memory p)
        internal view returns (bool found, uint256 wireType, bytes memory value)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.read, (message, p))), (bool, uint256, bytes));
    }

    function getAll(bytes memory message, uint256[] memory p)
        internal view returns (uint256[] memory wireTypes, bytes[] memory values)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.readAll, (message, p))), (uint256[], bytes[]));
    }

    function has(bytes memory message, uint256[] memory p) internal view returns (bool found) {
        (found,,) = get(message, p);
    }

    function getUint(bytes memory message, uint256[] memory p) internal view returns (uint256) {
        (,, bytes memory v) = get(message, p);
        return _word(v);
    }

    function getInt(bytes memory message, uint256[] memory p) internal view returns (int64) {
        return toInt(getUint(message, p));
    }

    function getSint(bytes memory message, uint256[] memory p) internal view returns (int64) {
        return toSint(getUint(message, p));
    }

    function getBool(bytes memory message, uint256[] memory p) internal view returns (bool) {
        return getUint(message, p) != 0;
    }

    function getBytes(bytes memory message, uint256[] memory p) internal view returns (bytes memory v) {
        (,, v) = get(message, p);
    }

    function getString(bytes memory message, uint256[] memory p) internal view returns (string memory) {
        return string(getBytes(message, p));
    }

    function getUints(bytes memory message, uint256[] memory p) internal view returns (uint256[] memory) {
        (uint256[] memory types, bytes[] memory values) = getAll(message, p);
        return _uints(types, values);
    }

    function getStrings(bytes memory message, uint256[] memory p) internal view returns (string[] memory out) {
        (, bytes[] memory values) = getAll(message, p);
        out = new string[](values.length);
        for (uint256 i; i < values.length; ++i) out[i] = string(values[i]);
    }

    function set(bytes memory message, uint256[] memory p, uint256 wireType, bytes memory value)
        internal view returns (bytes memory)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.write, (message, p, wireType, value))), (bytes));
    }

    function add(bytes memory message, uint256[] memory p, uint256 wireType, bytes memory value)
        internal view returns (bytes memory)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.append, (message, p, wireType, value))), (bytes));
    }

    function clear(bytes memory message, uint256[] memory p) internal view returns (bytes memory) {
        return abi.decode(_view(abi.encodeCall(IProtobuf.clear, (message, p))), (bytes));
    }

    function setUint(bytes memory message, uint256[] memory p, uint256 v) internal view returns (bytes memory) {
        return set(message, p, VARINT, abi.encode(v));
    }

    function setInt(bytes memory message, uint256[] memory p, int64 v) internal view returns (bytes memory) {
        return set(message, p, VARINT, abi.encode(fromInt(v)));
    }

    function setSint(bytes memory message, uint256[] memory p, int64 v) internal view returns (bytes memory) {
        return set(message, p, VARINT, abi.encode(fromSint(v)));
    }

    function setBool(bytes memory message, uint256[] memory p, bool v) internal view returns (bytes memory) {
        return set(message, p, VARINT, abi.encode(v ? 1 : 0));
    }

    function setBytes(bytes memory message, uint256[] memory p, bytes memory v) internal view returns (bytes memory) {
        return set(message, p, BYTES, v);
    }

    function setString(bytes memory message, uint256[] memory p, string memory v)
        internal view returns (bytes memory)
    {
        return set(message, p, BYTES, bytes(v));
    }

    function addUint(bytes memory message, uint256[] memory p, uint256 v) internal view returns (bytes memory) {
        return add(message, p, VARINT, abi.encode(v));
    }

    function addString(bytes memory message, uint256[] memory p, string memory v)
        internal view returns (bytes memory)
    {
        return add(message, p, BYTES, bytes(v));
    }

    // ------------------------------------------------------------------
    // Raw codec
    // ------------------------------------------------------------------

    function decode(bytes memory message)
        internal view returns (uint256[] memory fieldNumbers, uint256[] memory wireTypes, bytes[] memory values)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.decode, (message))), (uint256[], uint256[], bytes[]));
    }

    function encode(uint256[] memory fieldNumbers, uint256[] memory wireTypes, bytes[] memory values)
        internal view returns (bytes memory)
    {
        return abi.decode(_view(abi.encodeCall(IProtobuf.encode, (fieldNumbers, wireTypes, values))), (bytes));
    }

    function decodePacked(bytes memory data, uint256 wireType) internal view returns (uint256[] memory) {
        return abi.decode(_view(abi.encodeCall(IProtobuf.decodePacked, (data, wireType))), (uint256[]));
    }

    function encodePacked(uint256[] memory values, uint256 wireType) internal view returns (bytes memory) {
        return abi.decode(_view(abi.encodeCall(IProtobuf.encodePacked, (values, wireType))), (bytes));
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    function _view(bytes memory callData) private view returns (bytes memory ret) {
        bool ok;
        (ok, ret) = PRECOMPILE.staticcall(callData);
        if (!ok) revert ProtobufCallFailed();
    }

    function _write(bytes memory callData) private {
        (bool ok,) = PRECOMPILE.call(callData);
        if (!ok) revert ProtobufCallFailed();
    }

    function _word(bytes memory v) private pure returns (uint256) {
        return v.length == 32 ? abi.decode(v, (uint256)) : 0;
    }

    /// @dev Flattens a repeated numeric field: packed (bytes) entries are
    /// expanded as varints; for packed fixed32/fixed64 call decodePacked.
    function _uints(uint256[] memory types, bytes[] memory values) private view returns (uint256[] memory out) {
        uint256 n;
        uint256[][] memory parts = new uint256[][](values.length);
        for (uint256 i; i < values.length; ++i) {
            if (types[i] == BYTES) {
                parts[i] = decodePacked(values[i], VARINT);
            } else {
                parts[i] = new uint256[](1);
                parts[i][0] = _word(values[i]);
            }
            n += parts[i].length;
        }
        out = new uint256[](n);
        uint256 k;
        for (uint256 i; i < parts.length; ++i) {
            for (uint256 j; j < parts[i].length; ++j) out[k++] = parts[i][j];
        }
    }
}
