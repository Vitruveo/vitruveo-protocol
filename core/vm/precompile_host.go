package vm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/net/http/httpguts"
)

// HOST precompile (0x...99)
//
// Consensus side (RunHOST): the precompile charges a fixed gas cost, emits a
// HostRequested(requestId, caller) log and returns the requestId. It does not
// read the registry or touch anything validator-specific, so execution is
// identical on every node. Because the log is journaled like any other log, it
// disappears when the enclosing call frame or transaction reverts, and it only
// becomes visible outside the EVM through the receipts of a written block.
//
// Node side (LookupHostWebhook / FireHostWebhook): a node-level watcher
// (eth/host_webhook.go) follows the canonical chain, scans receipts for
// HostRequested logs and, on validators, re-reads the HostRequests registry
// against the post-state of the block that contained the call. Only then are
// secrets decrypted, templates filled and the payload signed and sent. Nothing
// decrypted is ever written to the chain or to logs.

var (
	HostRequestsContractAddress = common.HexToAddress("0xbdc8a59Ec92065848D0a6591F1a67Ce09D5E5FA7")
	getRequestSelector          = crypto.Keccak256([]byte("getRequest(uint256,address)"))[:4]

	// HostRequestedTopic is the topic0 of the log emitted by every successful
	// HOST call: HostRequested(uint256 indexed requestId, address indexed caller).
	HostRequestedTopic = crypto.Keccak256Hash([]byte("HostRequested(uint256,address)"))

	// HostStatsURL receives hourly delivery statistics. Empty disables reporting.
	HostStatsURL = "https://status.vitruveo.ai/webhook"

	// hostWebhookBackoff is the delay before each delivery attempt.
	hostWebhookBackoff = []time.Duration{
		0,
		10 * time.Second,
		30 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		30 * time.Minute,
		45 * time.Minute,
		60 * time.Minute,
	}

	firedRequests   sync.Map
	lastStatsReport int64
	statsReportMu   sync.Mutex
)

func init() {
	go func() {
		for {
			time.Sleep(24 * time.Hour)
			cutoff := time.Now().Unix() - 86400
			firedRequests.Range(func(k, v interface{}) bool {
				if v.(int64) < cutoff {
					firedRequests.Delete(k)
				}
				return true
			})
		}
	}()
}

const (
	HostGasCost = 25000
	// RegistryCallGas is no longer spent on a registry call during execution
	// (the registry is read by the node-level watcher) but is still charged so
	// the gas schedule of the precompile is unchanged.
	RegistryCallGas   = 100000
	MinRegistryReturn = 256
	MaxStringLength   = 1000000
	MaxArrayCount     = 1000

	// MaxFilledTemplateLength caps the size of a filled header or body
	// template, guarding against placeholder amplification.
	MaxFilledTemplateLength = 4 * MaxStringLength
)

// hostRequestID extracts the requestId from HOST input. The input is either
// abi.encode(uint256) or getRequest(uint256,address) calldata; shorter input
// is left-padded, longer input is truncated to the first word.
func hostRequestID(input []byte) common.Hash {
	data := input
	if len(input) >= 4 && bytes.Equal(input[:4], getRequestSelector) {
		data = input[4:]
	}
	if len(data) > 32 {
		data = data[:32]
	}
	return common.BytesToHash(data)
}

// RunHOST implements the HOST precompile. It is deterministic: it emits a
// HostRequested log and returns the 32-byte requestId. Webhook delivery is
// handled outside the EVM; see the comment at the top of this file.
//
// The log is emitted for STATICCALL invocations as well, so contracts that
// call HOST from a view function keep working.
func RunHOST(evm *EVM, caller common.Address, input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	totalCost := uint64(HostGasCost + RegistryCallGas)
	if suppliedGas < totalCost {
		return nil, 0, ErrOutOfGas
	}
	id := hostRequestID(input)
	evm.StateDB.AddLog(&types.Log{
		Address:     HOSTPrecompileAddress,
		Topics:      []common.Hash{HostRequestedTopic, id, common.BytesToHash(caller.Bytes())},
		BlockNumber: evm.Context.BlockNumber.Uint64(),
	})
	return id.Bytes(), suppliedGas - totalCost, nil
}

// HostRequestIDFromLog returns the requestId of a HostRequested log.
func HostRequestIDFromLog(l *types.Log) (*big.Int, bool) {
	if l == nil || l.Address != HOSTPrecompileAddress || len(l.Topics) < 2 || l.Topics[0] != HostRequestedTopic {
		return nil, false
	}
	return l.Topics[1].Big(), true
}

// HostWebhook is a fully built webhook ready for delivery. It contains
// decrypted values and must not be logged or persisted.
type HostWebhook struct {
	RequestID *big.Int
	URL       string
	Headers   map[string]string
	Body      []byte
	Signature string // 0x-prefixed signature over keccak256(Body)
	Pubkey    string // 0x-prefixed uncompressed validator public key
}

// hostRegistryEntry is the decoded getRequest return value.
type hostRegistryEntry struct {
	url            string
	headerTemplate string
	headerValues   []string
	bodyTemplate   string
	bodyValues     []string
}

// LookupHostWebhook queries the registry via evm (which should be backed by
// the state the request was observed in) on behalf of the validator owning
// key. It returns (nil, nil) if the registry says this validator should not
// process the request.
func LookupHostWebhook(evm *EVM, requestId *big.Int, key *ecdsa.PrivateKey) (hook *HostWebhook, err error) {
	if key == nil {
		return nil, errors.New("no validator key")
	}
	defer func() {
		if r := recover(); r != nil {
			hook, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	validator := crypto.PubkeyToAddress(key.PublicKey)

	calldata := make([]byte, 0, 4+64)
	calldata = append(calldata, getRequestSelector...)
	calldata = append(calldata, common.BigToHash(requestId).Bytes()...)
	calldata = append(calldata, common.LeftPadBytes(validator.Bytes(), 32)...)

	ret, _, err := evm.StaticCall(AccountRef(common.Address{}), HostRequestsContractAddress, calldata, RegistryCallGas)
	if err != nil {
		return nil, fmt.Errorf("registry call failed: %w", err)
	}
	entry, ok := parseHostRegistryResponse(ret)
	if !ok {
		return nil, nil
	}
	return buildHostWebhook(requestId, entry, key)
}

// parseHostRegistryResponse decodes getRequest's return data. ok is false if
// the response is malformed or shouldProcess is false.
func parseHostRegistryResponse(regRet []byte) (entry *hostRegistryEntry, ok bool) {
	if len(regRet) < MinRegistryReturn {
		return nil, false
	}
	safeReadWord := func(pos int) []byte {
		if pos < 0 || pos+32 > len(regRet) {
			return nil
		}
		return regRet[pos : pos+32]
	}
	shouldProcessWord := safeReadWord(0)
	if shouldProcessWord == nil || new(big.Int).SetBytes(shouldProcessWord).Sign() == 0 {
		return nil, false
	}

	safeToInt := func(b []byte) int {
		if b == nil {
			return -1
		}
		v := new(big.Int).SetBytes(b)
		if !v.IsUint64() || v.Uint64() > uint64(len(regRet)) {
			return -1
		}
		return int(v.Uint64())
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
			if pos+32 > len(regRet) {
				break
			}
			strRelOffset := safeToInt(regRet[pos : pos+32])
			if strRelOffset < 0 {
				continue
			}
			strAbsOffset := dataStart + strRelOffset
			if strAbsOffset+32 > len(regRet) {
				continue
			}
			strLen := safeToInt(regRet[strAbsOffset : strAbsOffset+32])
			if strLen < 0 || strLen > MaxStringLength {
				continue
			}
			start := strAbsOffset + 32
			end := start + strLen
			if end <= len(regRet) {
				result = append(result, string(regRet[start:end]))
			}
		}
		return result
	}

	return &hostRegistryEntry{
		url:            safeReadDynamicString(safeReadWord(64)),
		headerTemplate: safeReadDynamicString(safeReadWord(96)),
		headerValues:   safeReadStringArray(safeReadWord(128)),
		bodyTemplate:   safeReadDynamicString(safeReadWord(160)),
		bodyValues:     safeReadStringArray(safeReadWord(192)),
	}, true
}

// buildHostWebhook decrypts template values, fills the templates and signs
// the body.
func buildHostWebhook(requestId *big.Int, e *hostRegistryEntry, key *ecdsa.PrivateKey) (*HostWebhook, error) {
	if e.url == "" || (!strings.HasPrefix(e.url, "http://") && !strings.HasPrefix(e.url, "https://")) {
		return nil, fmt.Errorf("invalid url %q", e.url)
	}
	headers := make(map[string]string)
	if e.headerTemplate != "" {
		// Header templates are always JSON objects of string values.
		filled, err := fillHostTemplate(e.headerTemplate, resolveHostValues(e.headerValues, key), true)
		if err != nil {
			return nil, fmt.Errorf("header template: %w", err)
		}
		if err := json.Unmarshal([]byte(filled), &headers); err != nil {
			log.Warn("HOST: Header unmarshal failed", "id", requestId, "err", err)
			headers = make(map[string]string)
		}
		for k, v := range headers {
			if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) {
				log.Warn("HOST: Dropping invalid header", "id", requestId, "name", k)
				delete(headers, k)
			}
		}
	}
	body, err := fillHostTemplate(e.bodyTemplate, resolveHostValues(e.bodyValues, key), isJSONTemplate(e.bodyTemplate))
	if err != nil {
		return nil, fmt.Errorf("body template: %w", err)
	}
	hook := &HostWebhook{
		RequestID: new(big.Int).Set(requestId),
		URL:       e.url,
		Headers:   headers,
		Body:      []byte(body),
	}
	sig, err := crypto.Sign(crypto.Keccak256(hook.Body), key)
	if err != nil {
		log.Error("HOST: Failed to sign payload", "id", requestId, "err", err)
	} else {
		hook.Signature = "0x" + hex.EncodeToString(sig)
		hook.Pubkey = "0x" + hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
	}
	return hook, nil
}

// resolveHostValues decrypts values carrying the "|" prefix (hex ECDH
// ciphertext addressed to the validator). Other values pass through as is.
func resolveHostValues(values []string, key *ecdsa.PrivateKey) []string {
	const magicPrefix = "|"
	out := make([]string, len(values))
	for i, rawVal := range values {
		out[i] = rawVal
		trimmed := strings.Trim(strings.TrimSpace(rawVal), "\x00")
		if !strings.HasPrefix(trimmed, magicPrefix) {
			continue
		}
		hexStr := strings.TrimPrefix(trimmed, magicPrefix)
		out[i] = hexStr
		if hexStr == "" {
			continue
		}
		hexStr = strings.TrimPrefix(strings.TrimPrefix(hexStr, "0x"), "0X")
		cipherBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			log.Error("HOST: Hex decode failed", "err", err)
			continue
		}
		decrypted, err := decryptECDH(cipherBytes, key)
		if err != nil {
			log.Error("HOST: Decrypt failed", "err", err)
			continue
		}
		out[i] = string(decrypted)
	}
	return out
}

// isJSONTemplate reports whether a body template is treated as JSON: its first
// non-whitespace character is '{' or '['. Header templates are always JSON.
func isJSONTemplate(t string) bool {
	t = strings.TrimLeft(t, " \t\r\n")
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

// fillHostTemplate substitutes placeholders in template with values.
//
// Placeholders: "$" followed by the longest run of decimal digits, so "$10" is
// placeholder 10, never placeholder 1 followed by "0". Indices are 1-based.
// A placeholder whose index has a leading zero, is 0, or exceeds len(values)
// is left unchanged in the output. Substitution is single-pass: "$N" inside a
// substituted value is not expanded again.
//
// When jsonMode is false, values are inserted verbatim.
//
// When jsonMode is true, the template is scanned as JSON to track whether a
// placeholder sits inside a string literal:
//   - inside a string, the value is escaped as JSON string content (quotes,
//     backslashes, control characters such as newlines), so it can never
//     terminate the string or alter the surrounding structure;
//   - outside a string (e.g. {"amount": $1}), the value is inserted verbatim
//     only if it is exactly one valid JSON value (number, true/false/null,
//     string, object or array); otherwise it is inserted as a quoted JSON
//     string.
//
// Within a JSON string, a backslash escapes the next character, so "\$1" is
// not a placeholder.
func fillHostTemplate(template string, values []string, jsonMode bool) (string, error) {
	var b strings.Builder
	b.Grow(len(template))
	inString := false
	for i := 0; i < len(template); {
		if b.Len() > MaxFilledTemplateLength {
			return "", fmt.Errorf("filled template exceeds %d bytes", MaxFilledTemplateLength)
		}
		c := template[i]
		if c == '$' && i+1 < len(template) && isASCIIDigit(template[i+1]) {
			j := i + 1
			for j < len(template) && isASCIIDigit(template[j]) {
				j++
			}
			if idx, ok := placeholderIndex(template[i+1:j], len(values)); ok {
				v := values[idx-1]
				switch {
				case !jsonMode:
					b.WriteString(v)
				case inString:
					b.WriteString(jsonStringContent(v))
				case json.Valid([]byte(v)):
					b.WriteString(v)
				default:
					b.WriteByte('"')
					b.WriteString(jsonStringContent(v))
					b.WriteByte('"')
				}
			} else {
				b.WriteString(template[i:j])
			}
			i = j
			continue
		}
		if jsonMode {
			if inString && c == '\\' && i+1 < len(template) {
				b.WriteString(template[i : i+2])
				i += 2
				continue
			}
			if c == '"' {
				inString = !inString
			}
		}
		b.WriteByte(c)
		i++
	}
	if b.Len() > MaxFilledTemplateLength {
		return "", fmt.Errorf("filled template exceeds %d bytes", MaxFilledTemplateLength)
	}
	return b.String(), nil
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// placeholderIndex parses a placeholder's digits and checks it is in 1..n
// without a leading zero.
func placeholderIndex(digits string, n int) (int, bool) {
	if len(digits) == 0 || digits[0] == '0' || len(digits) > 9 {
		return 0, false
	}
	idx, err := strconv.Atoi(digits)
	if err != nil || idx < 1 || idx > n {
		return 0, false
	}
	return idx, true
}

// jsonStringContent returns s escaped for use inside a JSON string literal,
// without the surrounding quotes. HTML characters are not escaped.
func jsonStringContent(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return ""
	}
	out := buf.Bytes() // "<escaped>"\n
	return string(out[1 : len(out)-2])
}

func decryptECDH(ciphertext []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	if len(ciphertext) < 93 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if key == nil {
		return nil, fmt.Errorf("no validator key")
	}

	ephemeralPub := ciphertext[:65]
	nonce := ciphertext[65:77]
	encrypted := ciphertext[77:]

	x, y := elliptic.Unmarshal(crypto.S256(), ephemeralPub)
	if x == nil {
		return nil, fmt.Errorf("invalid ephemeral pubkey")
	}

	sx, _ := crypto.S256().ScalarMult(x, y, key.D.Bytes())
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

// HostRequestFired reports whether a webhook was already fired for requestId.
func HostRequestFired(requestId *big.Int) bool {
	_, ok := firedRequests.Load(requestId.String())
	return ok
}

// MarkHostRequestFired records requestId as fired. It returns false if it was
// already recorded, in which case the caller must not fire it again.
func MarkHostRequestFired(requestId *big.Int) bool {
	_, loaded := firedRequests.LoadOrStore(requestId.String(), time.Now().Unix())
	return !loaded
}

// FireHostWebhook delivers hook with retries until a 200 response, the
// retry schedule is exhausted or ctx is canceled. Deduplication is the
// caller's responsibility (see MarkHostRequestFired).
func FireHostWebhook(ctx context.Context, hook *HostWebhook) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("HOST WEBHOOK: Panic", "err", r)
		}
	}()
	requestId := hook.RequestID

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}},
		Timeout:   5 * time.Second,
	}

	var (
		finalStatus  int
		finalAttempt int
		success      bool
	)
	for attempt, delay := range hostWebhookBackoff {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				log.Warn("HOST WEBHOOK: Aborted", "id", requestId, "attempt", attempt+1)
				return
			case <-timer.C:
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "POST", hook.URL, bytes.NewReader(hook.Body))
		if err != nil {
			cancel()
			log.Warn("HOST WEBHOOK: Request creation failed", "id", requestId, "attempt", attempt+1, "err", err)
			return
		}
		req.Header.Set("User-Agent", "Vitruveo-HOST/1.0")
		req.Header.Set("X-HOST-Request-ID", requestId.String())
		if hook.Signature != "" {
			req.Header.Set("X-HOST-Signature", hook.Signature)
			req.Header.Set("X-HOST-Pubkey", hook.Pubkey)
		}
		if _, ok := hook.Headers["Content-Type"]; !ok {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hook.Headers {
			if k != "User-Agent" {
				req.Header.Set(k, v)
			}
		}

		resp, err := client.Do(req)
		cancel()
		finalAttempt = attempt + 1
		if err != nil {
			log.Warn("HOST WEBHOOK: Request failed", "id", requestId, "attempt", attempt+1, "err", err)
			continue
		}
		resp.Body.Close()
		finalStatus = resp.StatusCode

		if resp.StatusCode == http.StatusOK {
			log.Info("HOST WEBHOOK: FIRED", "id", requestId, "status", resp.StatusCode, "attempt", attempt+1)
			success = true
			break
		}
		log.Warn("HOST WEBHOOK: Non-200 response", "id", requestId, "status", resp.StatusCode, "attempt", attempt+1)
	}
	if !success {
		log.Error("HOST WEBHOOK: Gave up after all retries", "id", requestId)
	}
	go reportStats(requestId, hook.Pubkey, hook.URL, finalStatus, finalAttempt, success)
}

func reportStats(requestId *big.Int, pubkey string, targetURL string, status int, attempts int, success bool) {
	statsURL := HostStatsURL
	if statsURL == "" {
		return
	}
	statsReportMu.Lock()
	now := time.Now().Unix()
	if now-lastStatsReport < 3600 {
		statsReportMu.Unlock()
		return
	}
	lastStatsReport = now
	statsReportMu.Unlock()

	defer func() {
		recover()
	}()

	stats := map[string]interface{}{
		"requestId": requestId.String(),
		"validator": pubkey,
		"targetURL": targetURL,
		"status":    status,
		"attempts":  attempts,
		"success":   success,
		"timestamp": now,
	}

	payload, _ := json.Marshal(stats)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", statsURL, bytes.NewBuffer(payload))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vitruveo-HOST/1.0")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
