package vm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

var (
	HostRequestsContractAddress = common.HexToAddress("0xbdc8a59Ec92065848D0a6591F1a67Ce09D5E5FA7")
	getRequestSelector          = crypto.Keccak256([]byte("getRequest(uint256,address)"))[:4]
)

const (
	HostGasCost       = 25000
	RegistryCallGas   = 100000 // We will charge this FLAT rate
	MinRegistryReturn = 256
	MaxStringLength   = 1000000
	MaxArrayCount     = 1000
)

func RunHOST(evm *EVM, input []byte, suppliedGas uint64) (ret []byte, gasLeft uint64, err error) {
	// 1. Gas Check & Flat Fee Deduction
	// To prevent forks, we charge the MAXIMUM possible cost upfront.
	// Every node pays (25k + 100k) = 125k gas, regardless of execution path.
	totalCost := uint64(HostGasCost + RegistryCallGas)
	if suppliedGas < totalCost {
		return nil, 0, ErrOutOfGas
	}
	gasLeft = suppliedGas - totalCost

	defer func() {
		if r := recover(); r != nil {
			log.Error("HOST: Panic recovered in RunHOST", "err", r)
			ret = nil
			gasLeft = 0
			err = ErrExecutionReverted
		}
	}()

	// 2. Parse Request ID
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

	// Helper to return the RequestID (This ensures EVM return value is consistent for everyone)
	returnRequestID := func() ([]byte, uint64, error) {
		return math.PaddedBigBytes(requestId, 32), gasLeft, nil
	}

	// 3. Determine "My Address" (Consensus Safe)
	// Standard nodes (non-validators) don't have a GlobalValidatorKey.
	// They must use a zero address so they can still run the StaticCall (and pay the gas)
	// without crashing or taking a cheaper code path.
	var myAddress common.Address
	if crypto.GlobalValidatorKey != nil {
		myAddress = crypto.PubkeyToAddress(crypto.GlobalValidatorKey.PublicKey)
	} else {
		myAddress = common.Address{} // Zero address for observers/syncing nodes
	}

	// 4. Construct Calldata
	calldata := append(getRequestSelector, common.LeftPadBytes(requestId.Bytes(), 32)...)
	calldata = append(calldata, common.LeftPadBytes(myAddress.Bytes(), 32)...)

	// 5. Call Registry Contract
	// We pass 'RegistryCallGas' effectively as a cap.
	// Note: We do NOT add the refund back to gasLeft. The gas is "burned" to ensure consistency.
	regRet, _, regErr := evm.StaticCall(AccountRef(common.Address{}), HostRequestsContractAddress, calldata, RegistryCallGas)

	// If call failed or returned too little data, we are done.
	// (Gas is already paid, so no fork).
	if regErr != nil || len(regRet) < MinRegistryReturn {
		return returnRequestID()
	}

	// 6. Safe ABI Helper Closures
	safeReadWord := func(pos int) []byte {
		if pos < 0 || pos+32 > len(regRet) {
			return nil
		}
		return regRet[pos : pos+32]
	}

	// 7. Check shouldProcess flag
	shouldProcessWord := safeReadWord(0)
	if shouldProcessWord == nil {
		return returnRequestID()
	}
	shouldProcess := new(big.Int).SetBytes(shouldProcessWord)
	
	// If I am NOT the validator (or I am a public node), this will be false.
	// We return early here. Since gas was flat-fee, this early exit is safe.
	if shouldProcess.Cmp(big.NewInt(0)) == 0 {
		return returnRequestID()
	}

	// --- LOGIC BELOW THIS LINE ONLY RUNS IF WE ARE THE TARGET VALIDATOR ---
	// This is safe because:
	// 1. Gas was already deducted upfront.
	// 2. The return value to EVM (RequestID) is the same as the early exit.
	// 3. The only difference is side-effects (webhook), which are off-chain.

	safeToInt := func(b []byte) int {
		if b == nil { return -1 }
		val := new(big.Int).SetBytes(b).Uint64()
		if val > uint64(len(regRet)) { return -1 }
		return int(val)
	}

	safeReadDynamicString := func(offsetPtr []byte) string {
		offset := safeToInt(offsetPtr)
		if offset < 0 || offset+32 > len(regRet) { return "" }
		length := safeToInt(regRet[offset : offset+32])
		if length < 0 || length > MaxStringLength || offset+32+length > len(regRet) { return "" }
		return string(regRet[offset+32 : offset+32+length])
	}

	safeReadStringArray := func(offsetPtr []byte) []string {
		arrayOffset := safeToInt(offsetPtr)
		if arrayOffset < 0 || arrayOffset+32 > len(regRet) { return nil }
		count := safeToInt(regRet[arrayOffset : arrayOffset+32])
		if count < 0 || count > MaxArrayCount { return nil }

		result := make([]string, 0, count)
		dataStart := arrayOffset + 32
		for i := 0; i < count; i++ {
			pos := dataStart + (i * 32)
			if pos < 0 || pos+32 > len(regRet) { break }
			strRelOffset := safeToInt(regRet[pos : pos+32])
			if strRelOffset < 0 { continue }
			strAbsOffset := dataStart + strRelOffset
			if strAbsOffset < 0 || strAbsOffset+32 > len(regRet) { continue }
			strLen := safeToInt(regRet[strAbsOffset : strAbsOffset+32])
			if strLen < 0 || strLen > MaxStringLength { continue }
			start := strAbsOffset + 32
			end := start + strLen
			if start >= 0 && end <= len(regRet) {
				result = append(result, string(regRet[start:end]))
			}
		}
		return result
	}

	url := safeReadDynamicString(safeReadWord(32))
	headerTemplate := safeReadDynamicString(safeReadWord(64))
	headerValues := safeReadStringArray(safeReadWord(96))
	bodyTemplate := safeReadDynamicString(safeReadWord(128))
	bodyValues := safeReadStringArray(safeReadWord(160))

	finalHeadersStr := safeFillTemplate(headerTemplate, headerValues)
	headerMap := make(map[string]string)
	if len(finalHeadersStr) > 0 {
		json.Unmarshal([]byte(finalHeadersStr), &headerMap)
	}

	finalBody := safeFillTemplate(bodyTemplate, bodyValues)

	// Chain of Custody (Signing)
	var signatureHex string
	var pubkeyHex string
	if crypto.GlobalValidatorKey != nil {
		hash := crypto.Keccak256([]byte(finalBody))
		sig, err := crypto.Sign(hash, crypto.GlobalValidatorKey)
		if err == nil {
			signatureHex = "0x" + hex.EncodeToString(sig)
			pubkeyBytes := crypto.FromECDSAPub(&crypto.GlobalValidatorKey.PublicKey)
			pubkeyHex = "0x" + hex.EncodeToString(pubkeyBytes)
		}
	}

	go fireWebhook(url, []byte(finalBody), headerMap, requestId, signatureHex, pubkeyHex)

	return returnRequestID()
}

// ... [Helper functions safeFillTemplate, decryptECDH, fireWebhook remain the same] ...
func safeFillTemplate(template string, values []string) string {
	defer func() {
		if r := recover(); r != nil {
			log.Error("HOST: Panic in fillTemplate", "err", r)
		}
	}()

	if values == nil || len(values) == 0 {
		return template
	}

	const magicPrefix = "|"
	replacements := make([]string, 0, len(values)*2)

	for i, rawVal := range values {
		processedVal := rawVal
		trimmed := strings.TrimSpace(rawVal)

		if strings.HasPrefix(trimmed, magicPrefix) {
			potentialHex := strings.TrimPrefix(trimmed, magicPrefix)
			processedVal = potentialHex

			if len(potentialHex) > 0 {
				hexStr := potentialHex
				if strings.HasPrefix(hexStr, "0x") || strings.HasPrefix(hexStr, "0X") {
					hexStr = hexStr[2:]
				}

				if cipherBytes, err := hex.DecodeString(hexStr); err == nil {
					if decrypted, err := decryptECDH(cipherBytes); err == nil {
						processedVal = string(decrypted)
					} else {
						log.Trace("HOST: Decrypt failed", "err", err)
					}
				} else {
					log.Trace("HOST: Hex decode failed", "err", err)
				}
			}
		}

		placeholder := fmt.Sprintf("$%d", i+1)
		replacements = append(replacements, placeholder, processedVal)
	}

	if len(replacements) == 0 {
		return template
	}
	return strings.NewReplacer(replacements...).Replace(template)
}

func decryptECDH(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 93 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if crypto.GlobalValidatorKey == nil {
		return nil, fmt.Errorf("no validator key")
	}

	ephemeralPub := ciphertext[:65]
	nonce := ciphertext[65:77]
	encrypted := ciphertext[77:]

	x, y := elliptic.Unmarshal(crypto.S256(), ephemeralPub)
	if x == nil {
		return nil, fmt.Errorf("invalid ephemeral pubkey")
	}

	sx, _ := crypto.S256().ScalarMult(x, y, crypto.GlobalValidatorKey.D.Bytes())
	shared := make([]byte, 32)
	sxBytes := sx.Bytes()
	copy(shared[32-len(sxBytes):], sxBytes)

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, encrypted, nil)
}

func fireWebhook(url string, payload []byte, headers map[string]string, requestId *big.Int, signature string, pubkey string) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("HOST WEBHOOK: Panic", "err", r)
		}
	}()

	if url == "" || (!strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://")) {
		log.Warn("HOST WEBHOOK: Invalid URL", "url", url)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Warn("HOST WEBHOOK: Request creation failed", "err", err)
		return
	}

	req.Header.Set("User-Agent", "Vitruveo-HOST/1.0")
	req.Header.Set("X-HOST-Request-ID", requestId.String())

	if signature != "" {
		req.Header.Set("X-HOST-Signature", signature)
		req.Header.Set("X-HOST-Pubkey", pubkey)
	}

	if _, ok := headers["Content-Type"]; !ok {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range headers {
		if k != "User-Agent" {
			req.Header.Set(k, v)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Warn("HOST WEBHOOK: Request failed", "err", err)
		return
	}
	defer resp.Body.Close()

	log.Info("HOST WEBHOOK: FIRED", "id", requestId, "status", resp.StatusCode)
}