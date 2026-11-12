// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vitruveo randomness (RNG precompile at 0x00000000000000000000000000000000000000FF)
/// @notice Commit-reveal randomness that the requester cannot predict.
///
/// Flow:
///   1. id = commit(salt) in block N. Bind whatever depends on the outcome
///      (bet, mint, draw) in this same transaction.
///   2. From block N+2 until block N+1+256, anyone calls reveal(id). The result is
///      keccak256(requestSeed, blockhash(N+1)) and is stored permanently.
///   3. A request not revealed in that window expires (status 4). Since anyone can
///      reveal, the party that benefits from the result can always reveal in time;
///      a consumer contract must decide what an expired request means.
/// blockhash(N+1) does not exist when the commit is mined, so neither the sender
/// nor a contract simulating the call can know the result at commit time. The
/// sealer of block N+1 can still bias it by choosing that block's contents.
///
/// The precompile also accepts a plain (non-ABI) call; see VitruveoRandom.words.
/// Only an input of exactly 36 bytes starting with one of the selectors below is
/// treated as an ABI call.
interface IRandom {
    /// Emitted by commit().
    event RandomnessRequested(uint256 indexed id, address indexed owner, uint256 revealBlock);
    /// Emitted by the first successful reveal().
    event RandomnessRevealed(uint256 indexed id, address indexed owner, bytes32 randomness);
    /// Emitted by a plain call outside a static context. callIndex is the
    /// per-transaction call counter; seed expands to the returned words as
    /// keccak256(seed, uint64(i)).
    event RandomWords(address indexed caller, uint256 indexed callIndex, bytes32 seed, uint256 count);

    /// Records a request owned by msg.sender. Not allowed in a static call.
    function commit(bytes32 salt) external returns (uint256 id);

    /// Stores and returns the result. Callable by anyone; returns the stored value
    /// if already revealed (also in a static call). Reverts with Error(string) if
    /// the request is unknown, not yet revealable, or expired.
    function reveal(uint256 id) external returns (bytes32 randomness);

    /// Result if revealed or revealable now, without storing it.
    function getRandomness(uint256 id) external view returns (bool ready, bytes32 randomness);

    /// status: 0 none, 1 pending (before block revealBlock+1), 2 ready, 3 revealed, 4 expired
    function getRequest(uint256 id)
        external
        view
        returns (address owner, uint256 commitBlock, uint256 revealBlock, uint256 status);
}

/// @title Vitruveo shuffle (precompile at 0x00000000000000000000000000000000000000AB)
/// @notice Input is an optional salt; output is a 104-byte deck of 52 cards, each
/// [suit][rank] in ASCII (suits S H D C, ranks A 2-9 T J Q K).
interface IShuffle {
    /// Emitted outside a static context.
    event Shuffled(address indexed caller, uint256 indexed callIndex, bytes32 seed);
}

/// @notice Helpers for the plain-call formats of the RNG and Shuffle precompiles.
///
/// PLAIN CALLS ARE NOT SECURE AGAINST A USER WHO CAN SIMULATE. Their seed comes
/// from the parent hash, block difficulty, origin, origin nonce, timestamp, chain
/// ID, caller, a per-transaction call counter and the salt. Under Clique all of
/// these are known before the transaction is mined, and a contract can revert on
/// an unfavorable outcome. Use IRandom commit-reveal when the outcome has value;
/// passing a revealed value as the salt makes words() and shuffle() unpredictable.
///
/// Each call in a transaction returns different values. In a static call (from a
/// view function) the counter cannot advance and no event is emitted; identical
/// static calls may return the same value, so pass distinct salts.
library VitruveoRandom {
    address internal constant RNG = 0x00000000000000000000000000000000000000ff;
    address internal constant SHUFFLE = 0x00000000000000000000000000000000000000AB;

    /// `count` (0-255) random words. Input format: [uint8 count][salt bytes].
    /// Avoid a 35-byte salt: a 36-byte input that starts with an IRandom
    /// selector is decoded as that function.
    function words(uint8 count, bytes memory salt) internal returns (uint256[] memory) {
        (bool ok, bytes memory ret) = RNG.call(abi.encodePacked(count, salt));
        require(ok, "RNG failed");
        return abi.decode(ret, (uint256[]));
    }

    /// 104-byte shuffled deck. Input format: [salt bytes].
    function shuffle(bytes memory salt) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = SHUFFLE.call(salt);
        require(ok && ret.length == 104, "shuffle failed");
        return ret;
    }
}
