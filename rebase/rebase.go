package rebase

import (
	"math/big"

	"github.com/ethereum/go-ethereum/log"
)

var BLOCKS_PER_EPOCH = big.NewInt(17280)

const START_TX_GOAL = uint64(10000)
const EPOCH_TX_INCREMENT = uint64(500)
const INTEREST_PER_EPOCH = uint64(100087671)

var INITIAL_SUPPLY, _ = new(big.Int).SetString("60000000000000000000000000", 10) // 60 million
var MAX_SUPPLY, _ = new(big.Int).SetString("250000000000000000000000000", 10)    // 250 million

const UINT64_DIVISOR = uint64(100000000)

var DIVISOR = new(big.Int).Exp(big.NewInt(10), big.NewInt(8), nil)
var DECIMALS = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

type RebaseInfo struct {
	Epoch    uint64
	EpochTx  uint64
	Rbx      uint64
	RbxEpoch uint64
	Supply   *big.Int
	Perks    *big.Int
	Tx       uint64
}

func roundIfEndsIn9(n *big.Int) *big.Int {
    // Create a big.Int with the value 10 (to use for modulus)
    ten := big.NewInt(10)
    nine := big.NewInt(9)

    // Create a temporary big.Int to store the result of modulus
    modResult := new(big.Int)
    modResult.Mod(n, ten) // n % 10

    // Check if the last digit is 9
    if modResult.Cmp(nine) == 0 {
        // Add 1 to the original number
        n.Add(n, big.NewInt(1))
    }

    return n
}

func GetRebasedAmount(amount *big.Int, rbx uint64) *big.Int {
	rebasedAmount := new(big.Int).Mul(amount, new(big.Int).SetUint64(rbx))
	rebasedAmount.Div(rebasedAmount, DIVISOR)
	return roundIfEndsIn9(rebasedAmount)
}

func GetTransferAmount(amount *big.Int, rbx uint64) *big.Int {

	expandAmount := new(big.Int).Mul(amount, DIVISOR)
	senderAmount := new(big.Int).Div(expandAmount, new(big.Int).SetUint64(rbx))

	return roundIfEndsIn9(senderAmount)
}


func ProcessRebase(blockNumber *big.Int, last RebaseInfo, current RebaseInfo) (uint64, uint64, uint64, uint64, *big.Int) {

	epoch := last.Epoch
	epochTx := last.EpochTx
	rbx := last.Rbx
	rbxEpoch := last.RbxEpoch
	supply := GetRebasedAmount(INITIAL_SUPPLY, rbx)

	// A new epoch occurs when the block number is evenly divisible by Blocks_Per_Epoch
	newEpoch := new(big.Int).Mod(blockNumber, BLOCKS_PER_EPOCH)
	if newEpoch.Sign() == 0 && (supply.Cmp(MAX_SUPPLY) == -1) {

		// Epoch increment is conditional on meeting TX goal for epoch
		txGoal := START_TX_GOAL + (rbxEpoch * EPOCH_TX_INCREMENT)

		txRatio := (epochTx * 100) / txGoal

		// TX Goal was met
		if txRatio >= 100 {

			// Increment the rebase epoch
			rbxEpoch = rbxEpoch + 1
			rbx = (rbx * INTEREST_PER_EPOCH) / UINT64_DIVISOR
			log.Warn("Rebase Success 🎉", "Epoch", epoch, "RbxEpoch", rbxEpoch, "Rbx", rbx, "Goal", txGoal, "Supply", new(big.Int).Div(supply, DECIMALS))

		} else {
			log.Warn("Rebase Skipped 🙁", "Goal", txGoal, "Tx", epochTx)
		}

		// At every epoch the transaction count is always reset
		epochTx = current.Tx
		epoch = epoch + 1

	} else {

		epochTx = epochTx + current.Tx

	}

	return epoch, epochTx, rbx, rbxEpoch, supply
}
