package vm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// HOST Configuration
var (
	hostSignerAddress common.Address

	// HostRequestsContractAddress is the registry contract for HOST requests
	HostRequestsContractAddress = common.HexToAddress("0xbdc8a59Ec92065848D0a6591F1a67Ce09D5E5FA7")
)

func init() {
	// Scrape CLI for Validator Address
	for i, arg := range os.Args {
		if arg == "--unlock" || strings.HasPrefix(arg, "--unlock=") {
			var val string
			if strings.HasPrefix(arg, "--unlock=") {
				val = strings.TrimPrefix(arg, "--unlock=")
			} else if i+1 < len(os.Args) {
				val = os.Args[i+1]
			}
			candidates := strings.Split(val, ",")
			for _, c := range candidates {
				cleaned := strings.Trim(strings.TrimSpace(c), `"'`)
				if common.IsHexAddress(cleaned) {
					hostSignerAddress = common.HexToAddress(cleaned)
					log.Info("HOST INIT: Signer Found", "address", hostSignerAddress.Hex())
					return
				}
			}
		}
	}
	log.Warn("HOST INIT: No signer found (did you use --unlock?)")
}

// RunHOST executes the HOST precompile logic
func RunHOST(evm *EVM, input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	const gasCost = 25000
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	remainingGas := suppliedGas - gasCost

	// 1. Robust Input Parsing
	var requestIdBytes []byte
	data := input
	if len(input) >= 36 {
		data = input[4:] // Strip selector if present
	}
	if len(data) > 32 {
		requestIdBytes = data[:32]
	} else {
		requestIdBytes = common.LeftPadBytes(data, 32)
	}
	requestId := new(big.Int).SetBytes(requestIdBytes)

	log.Info("HOST EXEC: Lookup", "id", requestId)

	// 2. Call Registry Contract
	selector := crypto.Keccak256([]byte("getRequest(uint256)"))[:4]
	calldata := append(selector, common.LeftPadBytes(requestId.Bytes(), 32)...)

	ret, _, err := evm.StaticCall(AccountRef(common.Address{}), HostRequestsContractAddress, calldata, 100000)
	if err != nil {
		log.Warn("HOST EXEC: Registry Call Failed", "id", requestId, "err", err)
		return math.PaddedBigBytes(requestId, 32), remainingGas, nil
	}

	if len(ret) == 0 {
		log.Warn("HOST EXEC: Registry Empty Return", "id", requestId)
		return math.PaddedBigBytes(requestId, 32), remainingGas, nil
	}

	// 3. Manual ABI Decoding
	readWord := func(offset int) []byte {
		if offset+32 > len(ret) {
			return nil
		}
		return ret[offset : offset+32]
	}
	readDynamic := func(offsetPtr []byte) ([]byte, error) {
		if offsetPtr == nil {
			return nil, nil
		}
		offset := int(new(big.Int).SetBytes(offsetPtr).Uint64())
		if offset >= len(ret) {
			return nil, nil
		}
		lenBytes := readWord(offset)
		if lenBytes == nil {
			return nil, nil
		}
		length := int(new(big.Int).SetBytes(lenBytes).Uint64())
		start := offset + 32
		end := start + length
		if end > len(ret) {
			return nil, nil
		}
		return ret[start:end], nil
	}

	// Registry Tuple: (url, payload, headers, nodes, expireTime)
	expireTime := new(big.Int).SetBytes(readWord(128))

	// 4. Expiration Check
	if uint64(time.Now().Unix()) > expireTime.Uint64() {
		log.Info("HOST EXEC: Request Expired", "id", requestId)
		return math.PaddedBigBytes(requestId, 32), remainingGas, nil
	}

	// 5. Node Selection Check
	shouldFire := false
	if hostSignerAddress != (common.Address{}) {
		nodesOffsetPtr := readWord(96)
		nodesOffset := int(new(big.Int).SetBytes(nodesOffsetPtr).Uint64())

		if nodesOffset+32 <= len(ret) {
			count := int(new(big.Int).SetBytes(ret[nodesOffset : nodesOffset+32]).Uint64())
			startPos := nodesOffset + 32
			for i := 0; i < count; i++ {
				p := startPos + (i * 32)
				if p+32 <= len(ret) {
					if common.BytesToAddress(ret[p+12:p+32]) == hostSignerAddress {
						shouldFire = true
						break
					}
				}
			}
		}
	}

	// 6. Fire Side Effect
	if shouldFire {
		urlBytes, _ := readDynamic(readWord(0))
		payload, _ := readDynamic(readWord(32))
		headersBytes, _ := readDynamic(readWord(64))

		if urlBytes != nil {
			go fireWebhook(string(urlBytes), common.CopyBytes(payload), string(headersBytes), requestId)
		}
	} else {
		log.Info("HOST EXEC: Node not selected", "id", requestId)
	}

	return math.PaddedBigBytes(requestId, 32), remainingGas, nil
}

func fireWebhook(url string, payload []byte, headersStr string, requestId *big.Int) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("HOST WEBHOOK: PANIC", "err", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		log.Error("HOST WEBHOOK: Creation Failed", "err", err)
		return
	}

	req.Header.Set("X-Chain-Request-ID", requestId.String())
	if !strings.Contains(strings.ToLower(headersStr), "content-type") {
		req.Header.Set("Content-Type", "application/json")
	}

	if len(headersStr) > 0 {
		var headerMap map[string]string
		if err := json.Unmarshal([]byte(headersStr), &headerMap); err == nil {
			for k, v := range headerMap {
				req.Header.Set(k, v)
			}
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Error("HOST WEBHOOK: Network Error", "err", err)
		return
	}
	defer resp.Body.Close()

	log.Info("HOST WEBHOOK: SUCCESS", "status", resp.StatusCode, "id", requestId)
}