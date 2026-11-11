package eth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
)

// fileGateway serves files stored through the file storage precompile at
// /file/<sha256>, optionally followed by an extension (/file/<sha256>.png).
// Files are rebuilt from the upload transactions in block bodies and checked
// against their SHA-256 before being served.
type fileGateway struct {
	chain *core.BlockChain
	cache *lru.SizeConstrainedCache[common.Hash, []byte]
}

const fileGatewayCacheSize = 256 << 20

func newFileGateway(chain *core.BlockChain) *fileGateway {
	return &fileGateway{
		chain: chain,
		cache: lru.NewSizeConstrainedCache[common.Hash, []byte](fileGatewayCacheSize),
	}
}

func (g *fileGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Range, If-None-Match, If-Modified-Since")
	h.Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Content-Type, Accept-Ranges, ETag")
	h.Set("Access-Control-Max-Age", "86400")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")

	switch r.Method {
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodGet, http.MethodHead:
	default:
		h.Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hash, ok := parseFileHash(strings.TrimPrefix(r.URL.Path, "/file/"))
	if !ok {
		http.Error(w, "invalid file hash", http.StatusBadRequest)
		return
	}
	statedb, err := g.chain.State()
	if err != nil {
		http.Error(w, "state unavailable", http.StatusServiceUnavailable)
		return
	}
	info, ok := vm.ReadFileStoreInfo(statedb, hash)
	if !ok {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	data, err := g.load(info)
	if err != nil {
		log.Warn("File gateway failed to rebuild file", "hash", hash, "err", err)
		http.Error(w, "file unavailable", http.StatusInternalServerError)
		return
	}
	ctype := info.ContentType
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
	var modified time.Time
	if header := g.chain.GetHeaderByNumber(info.Block); header != nil {
		modified = time.Unix(int64(header.Time), 0)
	}
	http.ServeContent(w, r, "", modified, bytes.NewReader(data))
}

// load rebuilds a file from its upload transactions.
func (g *fileGateway) load(info *vm.FileStoreInfo) ([]byte, error) {
	if data, ok := g.cache.Get(info.Hash); ok {
		return data, nil
	}
	data := make([]byte, 0, info.Size)
	for i, loc := range info.Chunks {
		block := g.chain.GetBlockByNumber(loc.Block)
		if block == nil {
			return nil, errFileGateway("missing block")
		}
		txs := block.Transactions()
		if loc.TxIndex >= uint64(len(txs)) {
			return nil, errFileGateway("missing transaction")
		}
		chunk, err := vm.FileStoreChunkData(txs[loc.TxIndex].Data(), info.Hash, uint64(i))
		if err != nil {
			return nil, err
		}
		data = append(data, chunk...)
	}
	if uint64(len(data)) != info.Size || sha256.Sum256(data) != info.Hash {
		return nil, errFileGateway("hash mismatch")
	}
	g.cache.Add(info.Hash, data)
	return data, nil
}

type errFileGateway string

func (e errFileGateway) Error() string { return string(e) }

// parseFileHash accepts a 64-character hex SHA-256, with or without 0x, and
// ignores anything after the first dot.
func parseFileHash(s string) (common.Hash, bool) {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 64 {
		return common.Hash{}, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, false
	}
	return common.BytesToHash(b), true
}
