package rebase

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

var BLOCKS_PER_EPOCH = big.NewInt(17280)

const START_TX_GOAL = uint64(10000)
const EPOCH_TX_INCREMENT = uint64(500)
const INTEREST_PER_EPOCH = uint64(100087671)

var INITIAL_SUPPLY, _ = new(big.Int).SetString("60000000000000000000000000", 10) // 60 million
var MAX_SUPPLY, _ = new(big.Int).SetString("250000000000000000000000000", 10)    // 250 million

var PERKS_EPOCH_COINS, _ = new(big.Int).SetString("19863013698630136986000", 10)
var PERKS_VAULT = common.HexToAddress("0x2b3c3fb089301488c96bbc6f55f167fd1b128e9f")
var PERKS_POOL = common.HexToAddress("0xec274828b11338a5fa5a0f83f60dad7be429f15c") //Deploy from 0xa52b723650dc4c2b982c87de55a1378571b28ab0

const UINT64_DIVISOR = uint64(100000000)

var DIVISOR = new(big.Int).Exp(big.NewInt(10), big.NewInt(8), nil)

type RebaseInfo struct {
	Epoch    uint64
	EpochTx  uint64
	Rbx      uint64
	RbxEpoch uint64
	Supply   *big.Int
	Perks    *big.Int
	Tx       uint64
}

func GetRebasedAmount(amount *big.Int, rbx uint64) *big.Int {
	rebasedAmount := new(big.Int).Mul(amount, new(big.Int).SetUint64(rbx))
	//log.Warn("GetRebased", "rebased", rebasedAmount, "rbx", rbx)
	rebasedAmount.Div(rebasedAmount, DIVISOR)

	//	log.Info("RebasedAmount", "address", "block", blockNumber, "rebase", rebase, "amount", amount, "rebasedAmount", rebasedAmount)
	return rebasedAmount
}

func GetTransferAmount(amount *big.Int, rbx uint64) *big.Int {

	expandAmount := new(big.Int).Mul(amount, DIVISOR)
	senderAmount := new(big.Int).Div(expandAmount, new(big.Int).SetUint64(rbx))

	return senderAmount
}

func ProcessRebase(blockNumber *big.Int, last RebaseInfo, current RebaseInfo) (uint64, uint64, uint64, uint64, *big.Int, *big.Int) {

	epoch := last.Epoch
	epochTx := last.EpochTx
	rbx := last.Rbx
	rbxEpoch := last.RbxEpoch
	supply := GetRebasedAmount(INITIAL_SUPPLY, rbx)
	perks := big.NewInt(0)

	// A new epoch occurs when the block number is evenly divisible by Blocks_Per_Epoch
	newEpoch := new(big.Int).Mod(blockNumber, BLOCKS_PER_EPOCH)
	if newEpoch.Sign() == 0 && (supply.Cmp(MAX_SUPPLY) == -1) {

		// Epoch increment is conditional on meeting at least 75% of TX goal for epoch
		txGoal := START_TX_GOAL + (rbxEpoch * EPOCH_TX_INCREMENT)

		txRatio := (epochTx * 100) / txGoal

		// TX Goal was met or exceeded
		if txRatio >= 75 {
			// Upper limit is 125%
			if txRatio > 125 {
				txRatio = 125
			}

			// Increment the rebase epoch
			rbxEpoch = rbxEpoch + 1
			interest := ((INTEREST_PER_EPOCH - UINT64_DIVISOR) * txRatio / 100) + UINT64_DIVISOR

			rbx = rbx * interest / UINT64_DIVISOR

			// Add perks coins conditionally
			// Actual addition handled at the next block in consensus/clique/Finalize #576
			// This conveys an intent to add...actual perks may not be added if
			// supply is depleted
			perks = PERKS_EPOCH_COINS

			log.Warn("Rebase Success 🎉🎉🎉", "Epoch", epoch, "RbxEpoch", rbxEpoch, "Rbx", rbx, "Ratio", txRatio, "Supply", supply)

		} else {
			log.Warn("Rebase Skipped 🙁", "Goal", txGoal, "TX", epochTx, "Ratio", txRatio)
		}

		// At every epoch the transaction count is always reset
		epochTx = current.Tx
		epoch = epoch + 1

	} else {

		epochTx = epochTx + current.Tx

	}

	return epoch, epochTx, rbx, rbxEpoch, supply, perks
}
