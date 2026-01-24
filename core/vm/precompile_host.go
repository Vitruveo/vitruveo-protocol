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
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

var (
	HostRequestsContractAddress = common.HexToAddress("0xbdc8a59Ec92065848D0a6591F1a67Ce09D5E5FA7")
	getRequestSelector          = crypto.Keccak256([]byte("getRequest(uint256,address)"))[:4]

	// GLOBAL FLAG: Set to true only when the miner is sealing a block.
	// This allows RunHOST to distinguish between "Mining" (Skip) and "Verifying" (Run).
	IsMining atomic.Bool
)

const (
	HostGasCost       = 25000
	RegistryCallGas   = 100000
	MinRegistryReturn = 256
	MaxStringLength   = 1000000
	MaxArrayCount     = 1000
)

// RunHOST executes the HOST precompile logic
func RunHOST(evm *EVM, input []byte, suppliedGas uint64) (ret []byte, gasLeft uint64, err error) {
	// 1. CAPTURE CONTEXT (Pure Go)
    // We capture this early to separate decision logic from execution logic.
    isMining := IsMining.Load()
    isValidator := crypto.GlobalValidatorKey != nil

    // 2. FLAT FEE (Consensus Critical)
    totalCost := uint64(HostGasCost + RegistryCallGas)
    if suppliedGas < totalCost {
        return nil, 0, ErrOutOfGas
    }
    gasLeft = suppliedGas - totalCost

    // Helper for returns
    returnRequestID := func() ([]byte, uint64, error) {
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
        return math.PaddedBigBytes(requestId, 32), gasLeft, nil
    }

    // 3. SETUP ADDRESS (Handle Observers vs Validators)
    // We CANNOT return early if key is nil, because we must warm the storage.
    // If we are an Observer, we just use the Zero Address. 
    // The Registry will likely return "shouldProcess: false", which is fine.
    var myAddress common.Address
    if isValidator {
        myAddress = crypto.PubkeyToAddress(crypto.GlobalValidatorKey.PublicKey)
    }

    // --- EXECUTION LOGIC (Runs on ALL nodes) ---

    defer func() {
        if r := recover(); r != nil {
            log.Error("HOST: Panic recovered in RunHOST", "err", r)
            ret = nil
            gasLeft = 0
            err = ErrExecutionReverted
        }
    }()

    // 4. Parse Request ID
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

	// 5. Call Registry Contract
	// We use the 'RegistryCallGas' budget we already paid for (TotalCost).
	calldata := append(getRequestSelector, common.LeftPadBytes(requestId.Bytes(), 32)...)
	calldata = append(calldata, common.LeftPadBytes(myAddress.Bytes(), 32)...)

	regRet, _, regErr := evm.StaticCall(AccountRef(common.Address{}), HostRequestsContractAddress, calldata, RegistryCallGas)

	// If empty/error, it means we are not the selected validator (or request invalid)
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

	// 7. Check shouldProcess flag (Offset 0)
	shouldProcessWord := safeReadWord(0)
	if shouldProcessWord == nil {
		return returnRequestID()
	}
	shouldProcess := new(big.Int).SetBytes(shouldProcessWord)
	if shouldProcess.Cmp(big.NewInt(0)) == 0 {
		return returnRequestID()
	}

	// 8. Extract Data Helpers
	safeToInt := func(b []byte) int {
		if b == nil {
			return -1
		}
		val := new(big.Int).SetBytes(b).Uint64()
		if val > uint64(len(regRet)) {
			return -1
		}
		return int(val)
	}

	safeReadDynamicString := func(offsetPtr []byte) string {
		offset := safeToInt(offsetPtr)
		if offset < 0 || offset+32 > len(regRet) {
			return ""
		}
		length := safeToInt(regRet[offset : offset+32])
		if length < 0 || length > MaxStringLength || offset+32+length > len(regRet) {
			return ""
		}
		return string(regRet[offset+32 : offset+32+length])
	}

	safeReadStringArray := func(offsetPtr []byte) []string {
		arrayOffset := safeToInt(offsetPtr)
		if arrayOffset < 0 || arrayOffset+32 > len(regRet) {
			return nil
		}
		count := safeToInt(regRet[arrayOffset : arrayOffset+32])
		if count < 0 || count > MaxArrayCount {
			return nil
		}

		result := make([]string, 0, count)
		dataStart := arrayOffset + 32

		for i := 0; i < count; i++ {
			pos := dataStart + (i * 32)
			if pos < 0 || pos+32 > len(regRet) {
				break
			}
			strRelOffset := safeToInt(regRet[pos : pos+32])
			if strRelOffset < 0 {
				continue
			}

			strAbsOffset := dataStart + strRelOffset

			if strAbsOffset < 0 || strAbsOffset+32 > len(regRet) {
				continue
			}
			strLen := safeToInt(regRet[strAbsOffset : strAbsOffset+32])
			if strLen < 0 || strLen > MaxStringLength {
				continue
			}
			start := strAbsOffset + 32
			end := start + strLen
			if start >= 0 && end <= len(regRet) {
				result = append(result, string(regRet[start:end]))
			}
		}
		return result
	}

	// 9. Extract Data
	// NEW OFFSETS due to `address validator` inserted at Word 1 (byte 32)
	// Word 0 (0): shouldProcess
	// Word 1 (32): validator (Skipped)
	// Word 2 (64): url
	// Word 3 (96): headerTemplate
	// Word 4 (128): headerValues
	// Word 5 (160): bodyTemplate
	// Word 6 (192): bodyValues

	url := safeReadDynamicString(safeReadWord(64))
	headerTemplate := safeReadDynamicString(safeReadWord(96))
	headerValues := safeReadStringArray(safeReadWord(128))
	bodyTemplate := safeReadDynamicString(safeReadWord(160))
	bodyValues := safeReadStringArray(safeReadWord(192))

	// 10. Process (Decryption)
	finalHeadersStr := safeFillTemplate(headerTemplate, headerValues)

	headerMap := make(map[string]string)
	if len(finalHeadersStr) > 0 {
		if err := json.Unmarshal([]byte(finalHeadersStr), &headerMap); err != nil {
			log.Warn("HOST: Header Unmarshal failed", "err", err)
		}
	}

	finalBody := safeFillTemplate(bodyTemplate, bodyValues)

	// 11. Chain of Custody (Signing)
	var signatureHex string
	var pubkeyHex string

	if crypto.GlobalValidatorKey != nil {
		hash := crypto.Keccak256([]byte(finalBody))
		sig, err := crypto.Sign(hash, crypto.GlobalValidatorKey)
		if err == nil {
			signatureHex = "0x" + hex.EncodeToString(sig)
			pubkeyBytes := crypto.FromECDSAPub(&crypto.GlobalValidatorKey.PublicKey)
			pubkeyHex = "0x" + hex.EncodeToString(pubkeyBytes)
		} else {
			log.Error("HOST: Failed to sign payload", "err", err)
		}
	}

	// 12. SIDE EFFECT (Pure Go - Isolated)
    // We use our locally captured variables. 
    // This logic touches NO EVM state, so it cannot cause a fork.

    if !isMining && isValidator {
        go fireWebhook(url, []byte(finalBody), headerMap, requestId, signatureHex, pubkeyHex)
    }

    return returnRequestID()
}

// safeFillTemplate processes template with decryption - never panics
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
		trimmed = strings.Trim(trimmed, "\x00") // Clean invisible chars

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
						log.Error("HOST: Decrypt failed", "err", err)
					}
				} else {
					log.Error("HOST: Hex decode failed", "err", err)
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

// decryptECDH decrypts using ECDH shared secret + AES-GCM
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