package vm

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common/math"
)

// TrendPrecompile implements Pretrend Protocol: OLS (Mode 1) & Buckets (Mode 2)
type TrendPrecompile struct{}

const (
	stride    = 40
	precision = 1000000000000000000 // 1e18
)

var (
	bigPrecision           = new(big.Int).SetInt64(precision)
	errInvalidInput        = errors.New("invalid input length")
	errInsufficientData    = errors.New("insufficient data points")
	errZeroDiv             = errors.New("division by zero in regression")
)

func RunTrend(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	p := &TrendPrecompile{}
	required := p.RequiredGas(input)
	if gas < required {
		return nil, 0, ErrOutOfGas
	}
	ret, err := p.Run(input)
	return ret, gas - required, err
}

func (p *TrendPrecompile) RequiredGas(input []byte) uint64 {
	return uint64(len(input)) * 20
}

func (p *TrendPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 1 {
		return nil, errInvalidInput
	}
	mode := input[0]
	data := input[1:]

	switch mode {
	case 0x01:
		return p.runFullAnalysis(data) // Renamed from runOLS
	case 0x02:
		return p.runVolatilityBuckets(data)
	default:
		return nil, errors.New("unknown mode")
	}
}

// ============================================================================
// MODE 1: ANALYSIS (Slope + R² + Volatility)
// ============================================================================

func (p *TrendPrecompile) runFullAnalysis(input []byte) ([]byte, error) {
	points, err := unpackAndDeduplicate(input)
	if err != nil {
		return nil, err
	}
	n := int64(len(points))
	if n < 2 {
		return nil, errInsufficientData
	}

	bigN := big.NewInt(n)
	sumX, sumY, sumXY := new(big.Int), new(big.Int), new(big.Int)
	sumXX, sumYY := new(big.Int), new(big.Int)

	for _, pt := range points {
		x := new(big.Int).SetUint64(pt.ts)
		y := pt.val

		sumX.Add(sumX, x)
		sumY.Add(sumY, y)
		sumXY.Add(sumXY, new(big.Int).Mul(x, y))
		sumXX.Add(sumXX, new(big.Int).Mul(x, x))
		sumYY.Add(sumYY, new(big.Int).Mul(y, y))
	}

	// --- 1. Slope Calculation (m) ---
	// Num = N * SumXY - SumX * SumY
	numM := new(big.Int).Sub(
		new(big.Int).Mul(bigN, sumXY),
		new(big.Int).Mul(sumX, sumY),
	)

	// DenomX = N * SumXX - SumX^2
	denomM := new(big.Int).Sub(
		new(big.Int).Mul(bigN, sumXX),
		new(big.Int).Mul(sumX, sumX),
	)

	if denomM.Sign() == 0 {
		return nil, errZeroDiv
	}

	// Calculate fitted trend % change
	term1 := new(big.Int).Mul(sumY, denomM)
	term2 := new(big.Int).Mul(numM, sumX)
	numB := new(big.Int).Sub(term1, term2)
	denomB := new(big.Int).Mul(bigN, denomM)

	getFitted := func(ts uint64) *big.Int {
		x := new(big.Int).SetUint64(ts)
		// Y = (numM * x * N + numB) / denomB
		termA := new(big.Int).Mul(numM, x)
		termA.Mul(termA, bigN)
		num := new(big.Int).Add(termA, numB)
		return num.Div(num, denomB)
	}

	startY := getFitted(points[0].ts)
	endY := getFitted(points[n-1].ts)

	var slopePct *big.Int
	if startY.Sign() == 0 {
		slopePct = big.NewInt(0)
	} else {
		delta := new(big.Int).Sub(endY, startY)
		delta.Mul(delta, bigPrecision)
		slopePct = delta.Div(delta, startY)
	}

	// --- 2. R-Squared (Confidence) ---
	// R² = (Numerator_XY)^2 / (Denom_X * Denom_Y)
	// DenomY = N * SumYY - SumY^2
	denomY := new(big.Int).Sub(
		new(big.Int).Mul(bigN, sumYY),
		new(big.Int).Mul(sumY, sumY),
	)

	rSquared := new(big.Int)
	// Guard: Both denominators must be positive for valid R²
	if denomM.Sign() > 0 && denomY.Sign() > 0 {
		numSq := new(big.Int).Mul(numM, numM)
		denomTotal := new(big.Int).Mul(denomM, denomY)
		
		rSquared.Mul(numSq, bigPrecision) // Scale 1e18
		rSquared.Div(rSquared, denomTotal)
	}

	// --- 3. Volatility (Sample Standard Deviation) ---
	// Var = denomY / (N * (N-1))
	// denomY is algebraically equivalent to N * Σ(y - ȳ)²
	
	nMinus1 := new(big.Int).Sub(bigN, big.NewInt(1))
	denomVar := new(big.Int).Mul(bigN, nMinus1)
	
	variance := new(big.Int).Div(denomY, denomVar)
	volatility := new(big.Int).Sqrt(variance)
	volatility.Mul(volatility, big.NewInt(1e16)) // Cosmetic scale

	// --- Pack 96 Bytes ---
	output := make([]byte, 96)
	copy(output[0:32], toInt256Bytes(slopePct))
	copy(output[32:64], math.PaddedBigBytes(rSquared, 32))
	copy(output[64:96], math.PaddedBigBytes(volatility, 32))

	return output, nil
}

// ============================================================================
// MODE 2: VOLATILITY BUCKETS
// ============================================================================

func (p *TrendPrecompile) runVolatilityBuckets(input []byte) ([]byte, error) {
	if len(input) < 8 {
		return nil, errInvalidInput
	}
	windowSize := binary.BigEndian.Uint64(input[:8])
	
	// Deduplicate Input
	points, err := unpackAndDeduplicate(input[8:])
	if err != nil {
		return nil, err
	}
	if len(points) < 2 {
		return nil, errInsufficientData
	}

	var deltas []*big.Int
	left := 0

	// Sliding Window Logic
	for right := 1; right < len(points); right++ {
		targetTime := points[right].ts
		if targetTime < windowSize { continue }
		cutoff := targetTime - windowSize

		// Find point closest to T-Window
		for left < right-1 && points[left+1].ts <= cutoff {
			left++
		}

		// Calculate Absolute % Change
		p1 := points[left]
		p2 := points[right]

		if p1.val.Sign() == 0 { continue }

		d := new(big.Int).Sub(p2.val, p1.val)
		d.Abs(d)
		d.Mul(d, bigPrecision)
		d.Div(d, p1.val)
		deltas = append(deltas, d)
	}

	if len(deltas) < 5 {
		return make([]byte, 128), nil
	}

	// Sort and Quintiles
	sort.Slice(deltas, func(i, j int) bool {
		return deltas[i].Cmp(deltas[j]) < 0
	})

	n := len(deltas)
	output := make([]byte, 0, 128)
	output = append(output, math.PaddedBigBytes(deltas[n*20/100], 32)...)
	output = append(output, math.PaddedBigBytes(deltas[n*40/100], 32)...)
	output = append(output, math.PaddedBigBytes(deltas[n*60/100], 32)...)
	output = append(output, math.PaddedBigBytes(deltas[n*80/100], 32)...)

	return output, nil
}

// ============================================================================
// HELPERS (Unpack + Dedupe)
// ============================================================================

type DataPoint struct {
	ts  uint64
	val *big.Int
}

func unpackAndDeduplicate(input []byte) ([]DataPoint, error) {
	if len(input)%stride != 0 {
		return nil, errInvalidInput
	}
	count := len(input) / stride
	if count == 0 {
		return nil, nil
	}

	// Pre-allocate max size, but we might return fewer due to dedupe
	points := make([]DataPoint, 0, count)

	for i := 0; i < count; i++ {
		offset := i * stride
		ts := binary.BigEndian.Uint64(input[offset : offset+8])
		valBytes := input[offset+8 : offset+40]
		val := new(big.Int).SetBytes(valBytes)

		// Last Write Wins Deduplication
		if len(points) > 0 {
			lastIdx := len(points) - 1
			if points[lastIdx].ts == ts {
				// Overwrite existing
				points[lastIdx].val = val
				continue
			}
			// Enforce Strict Ordering (Optional but recommended)
			if points[lastIdx].ts > ts {
				return nil, errors.New("unsorted timestamp")
			}
		}
		points = append(points, DataPoint{ts: ts, val: val})
	}
	return points, nil
}

func toInt256Bytes(n *big.Int) []byte {
	if n.Sign() >= 0 {
		return math.PaddedBigBytes(n, 32)
	}
	mask := new(big.Int).Lsh(big.NewInt(1), 256)
	nTC := new(big.Int).Add(mask, n)
	return math.PaddedBigBytes(nTC, 32)
}