package vm

import (
	"bytes"
	"context"
	"crypto/tls" 
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"
)


var (
	HostRequestsContractAddress = common.HexToAddress("0xbdc8a59Ec92065848D0a6591F1a67Ce09D5E5FA7")
	getRequestSelector          = crypto.Keccak256([]byte("getRequest(uint256)"))[:4]
)

// [FIX] Named constants for audit/maintainability
const (
	HostGasCost       = 25000  // WARNING: Ensure this is sufficient for your chain's economics
	RegistryCallGas   = 100000 
	MinRegistryReturn = 224    // Minimum bytes for the registry tuple
)

// RunHOST executes the HOST precompile logic
func RunHOST(evm *EVM, input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	if suppliedGas < HostGasCost {
		return nil, 0, ErrOutOfGas
	}
	remainingGas := suppliedGas - HostGasCost

	// 1. Parse Request ID
	var requestIdBytes []byte
	data := input
	if len(input) >= 4 && bytes.Equal(input[:4], getRequestSelector) {
		data = input[4:]
	}
	if len(data) > 32 {
		requestIdBytes = data[:32]
	} else {
		requestIdBytes = common.LeftPadBytes(data, 32)
	}
	requestId := new(big.Int).SetBytes(requestIdBytes)

	// 2. Call Registry Contract
	calldata := append(getRequestSelector, common.LeftPadBytes(requestId.Bytes(), 32)...)
	ret, _, err := evm.StaticCall(AccountRef(common.Address{}), HostRequestsContractAddress, calldata, RegistryCallGas)
	
	if err != nil || len(ret) < MinRegistryReturn {
		return math.PaddedBigBytes(requestId, 32), remainingGas, nil
	}

	// 3. ABI Helper Closures
	readWord := func(pos int) []byte { 
		if pos+32 > len(ret) { return nil }
		return ret[pos : pos+32] 
	}
	readDynamicString := func(offsetPtr []byte) string {
		if offsetPtr == nil { return "" }
		offset := int(new(big.Int).SetBytes(offsetPtr).Uint64())
		if offset+32 > len(ret) { return "" }
		length := int(new(big.Int).SetBytes(ret[offset : offset+32]).Uint64())
		if offset+32+length > len(ret) { return "" }
		return string(ret[offset+32 : offset+32+length])
	}
	readStringArray := func(offsetPtr []byte) []string {
		if offsetPtr == nil { return nil }
		arrayOffset := int(new(big.Int).SetBytes(offsetPtr).Uint64())
		if arrayOffset+32 > len(ret) { return nil }
		count := int(new(big.Int).SetBytes(ret[arrayOffset : arrayOffset+32]).Uint64())
		if count > 1000 {
			return nil
		}
		result := make([]string, 0, count)
		dataStart := arrayOffset + 32
		for i := 0; i < count; i++ {
			pos := dataStart + (i * 32)
			if pos+32 > len(ret) { break }
			strRelOffset := int(new(big.Int).SetBytes(ret[pos : pos+32]).Uint64())
			strAbsOffset := arrayOffset + 32 + strRelOffset
			if strAbsOffset+32 > len(ret) { continue }
			strLen := int(new(big.Int).SetBytes(ret[strAbsOffset : strAbsOffset+32]).Uint64())
			start := strAbsOffset + 32
			end := start + strLen
			if end <= len(ret) {
				result = append(result, string(ret[start:end]))
			}
		}
		return result
	}

	// 4. Extract Data
	url := readDynamicString(readWord(0))
	headerTemplate := readDynamicString(readWord(32))
	headerValues := readStringArray(readWord(64))
	bodyTemplate := readDynamicString(readWord(96))
	bodyValues := readStringArray(readWord(128))
	nodesOffsetPtr := readWord(160)
	expireTime := new(big.Int).SetBytes(readWord(192))

	// 5. Check Expiration
	if evm.Context.Time > expireTime.Uint64() {
		return math.PaddedBigBytes(requestId, 32), remainingGas, nil
	}

	// 6. Node Selection Logic
	shouldFire := false
	if crypto.GlobalValidatorKey != nil {
		myAddress := crypto.PubkeyToAddress(crypto.GlobalValidatorKey.PublicKey)
		
		if nodesOffsetPtr != nil {
			nodesOffset := int(new(big.Int).SetBytes(nodesOffsetPtr).Uint64())
			if nodesOffset+32 <= len(ret) {
				count := int(new(big.Int).SetBytes(ret[nodesOffset : nodesOffset+32]).Uint64())
				// [FIX] Document empty behavior
				// If count is 0, loop doesn't run, shouldFire remains false. Correct.
				startPos := nodesOffset + 32
				for i := 0; i < count; i++ {
					p := startPos + (i * 32)
					if p+32 <= len(ret) {
						if common.BytesToAddress(ret[p+12 : p+32]) == myAddress {
							shouldFire = true
							break
						}
					}
				}
			}
		}
	}

	// 7. Execution with Decryption
	if shouldFire {
		// A. Process Header Values (Decrypt + Substitute)
		finalHeadersStr := fillTemplate(headerTemplate, headerValues)
		
		headerMap := make(map[string]string)
		if len(finalHeadersStr) > 0 {
			if err := json.Unmarshal([]byte(finalHeadersStr), &headerMap); err != nil {
				// [FIX] Log swallowed error
				log.Warn("HOST: Header Unmarshal failed", "err", err, "json", finalHeadersStr)
			}
		}

		// B. Process Body Values (Decrypt + Substitute)
		finalBody := fillTemplate(bodyTemplate, bodyValues)

		go fireWebhook(url, []byte(finalBody), headerMap, requestId)
	}

	return math.PaddedBigBytes(requestId, 32), remainingGas, nil
}

// fillTemplate checks for "|" prefix, decrypts, and replaces $N placeholders
// [FIX] Uses NewReplacer to prevent recursive substitution injection
func fillTemplate(template string, values []string) string {
	const magicPrefix = "|"
	
	// Prepare pairs for strings.NewReplacer: [old1, new1, old2, new2...]
	replacements := make([]string, 0, len(values)*2)

	for i, rawVal := range values {
		processedVal := rawVal
		trimmed := strings.TrimSpace(rawVal)
		
		if strings.HasPrefix(trimmed, magicPrefix) {
			// 1. Strip Sentinel (Always strip on fallback per Spec)
			potentialHex := strings.TrimPrefix(trimmed, magicPrefix)
			processedVal = potentialHex // [FIX] Default to stripped value

			// 2. Logic: Bare pipe check & Hex normalization
			if len(potentialHex) > 0 { // [FIX] Prevent decrypting empty bytes
				if !strings.HasPrefix(potentialHex, "0x") {
					potentialHex = "0x" + potentialHex
				}

				// 3. Attempt Decrypt
				if bytes, err := hexutil.Decode(potentialHex); err == nil {
					if crypto.GlobalValidatorKey != nil {
						eciesKey := ecies.ImportECDSA(crypto.GlobalValidatorKey)
						if decrypted, err := eciesKey.Decrypt(bytes, nil, nil); err == nil {
							// Success: Use decrypted
							processedVal = string(decrypted)
						} else {
							log.Trace("HOST: Decrypt failed", "err", err)
						}
					}
				}
			}
		}

		// Add to replacer args
		placeholder := fmt.Sprintf("$%d", i+1)
		replacements = append(replacements, placeholder, processedVal)
	}

	// 4. Single-pass substitution
	if len(replacements) == 0 {
		return template
	}
	return strings.NewReplacer(replacements...).Replace(template)
}

func fireWebhook(url string, payload []byte, headers map[string]string, requestId *big.Int) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("HOST WEBHOOK: Panic", "err", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return
	}

	req.Header.Set("X-Chain-Request-ID", requestId.String())
	if _, ok := headers["Content-Type"]; !ok {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		// [SECURITY NOTICE] InsecureSkipVerify is TRUE to support internal private chain endpoints.
		// If you require strict TLS validation, set this to false.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		log.Info("HOST WEBHOOK: FIRED", "id", requestId, "status", resp.StatusCode)
	}
}