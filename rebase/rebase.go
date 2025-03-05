package rebase

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

var BLOCKS_PER_EPOCH = big.NewInt(17280)

const START_TX_GOAL = uint64(9999999)
const EPOCH_TX_INCREMENT = uint64(500)
const INTEREST_PER_EPOCH = uint64(100087671)

var INITIAL_SUPPLY, _ = new(big.Int).SetString("60000000000000000000000000", 10) // 60 million
var MAX_SUPPLY, _ = new(big.Int).SetString("250000000000000000000000000", 10)    // 250 million

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
	// Verificação de segurança para valores negativos
	if amount.Sign() < 0 {
		return new(big.Int).Set(common.Big0)
	}

	rebasedAmount := new(big.Int).Mul(amount, new(big.Int).SetUint64(rbx))
	//log.Warn("GetRebased", "rebased", rebasedAmount, "rbx", rbx)
	rebasedAmount.Div(rebasedAmount, DIVISOR)

	//	log.Info("RebasedAmount", "address", "block", blockNumber, "rebase", rebase, "amount", amount, "rebasedAmount", rebasedAmount)
	return rebasedAmount
}

func GetTransferAmount(amount *big.Int, rbx uint64) *big.Int {
	// Verificação de segurança para valores negativos
	if amount.Sign() < 0 {
		return new(big.Int).Set(common.Big0)
	}

	expandAmount := new(big.Int).Mul(amount, DIVISOR)
	senderAmount := new(big.Int).Div(expandAmount, new(big.Int).SetUint64(rbx))

	return senderAmount
}

func ProcessRebase(blockNumber *big.Int, last RebaseInfo, current RebaseInfo) (uint64, uint64, uint64, uint64, *big.Int, *big.Int) {
	// Verificação de segurança para valores negativos em blockNumber
	if blockNumber == nil || blockNumber.Sign() < 0 {
		log.Warn("ProcessRebase: Número de bloco negativo ou nulo detectado")
		return last.Epoch, last.EpochTx, last.Rbx, last.RbxEpoch, last.Supply, big.NewInt(0)
	}

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

			// Proteção contra overflow ou valores inválidos
			if interest > 0 {
				rbx = rbx * interest / UINT64_DIVISOR
			} else {
				log.Warn("ProcessRebase: Proteção contra interesse inválido", "interest", interest)
			}

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
