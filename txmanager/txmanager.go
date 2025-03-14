// Package txmanager implements a transaction batching system to control transaction flow
// during rebasing periods in the Vitruveo blockchain.
package txmanager

import (
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rebase"
)

// Config para o gerenciador de transações
type Config struct {
	// Número máximo de transações por batch
	MaxBatchSize int
	// Intervalo de tempo para enviar um batch mesmo que incompleto
	BatchInterval time.Duration
	// Número máximo de transações por conta em um único bloco durante rebasing
	MaxTxPerAccountDuringRebase int
	// Flag para diminuir o batching durante blocos próximos ao rebasing
	ThrottleNearRebasing bool
	// Número de blocos antes do rebasing para iniciar o controle
	BlocksBeforeRebasingToThrottle int
}

// TxManager gerencia filas de transações com batching
type TxManager struct {
	config Config
	
	queue      map[common.Address][]*types.Transaction
	queueMutex sync.Mutex
	
	// Canal para sinalizar novas transações
	newTx chan struct{}
	// Controle de saldo e nonce por conta
	accounts map[common.Address]*accountInfo
	
	blockchain *core.BlockChain
	txpool     core.TxPool
	wg         sync.WaitGroup
	quit       chan struct{}
}

type accountInfo struct {
	pendingNonce uint64
	txCount      int // contador de transações por bloco
}

// DefaultConfig retorna a configuração padrão para o gerenciador de transações
func DefaultConfig() Config {
	return Config{
		MaxBatchSize:                  100,
		BatchInterval:                  2 * time.Second,
		MaxTxPerAccountDuringRebase:    5,
		ThrottleNearRebasing:           true,
		BlocksBeforeRebasingToThrottle: 10,
	}
}

// New cria um novo gerenciador de transações
func New(txpool core.TxPool, blockchain *core.BlockChain, config Config) *TxManager {
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = 100
	}
	if config.BatchInterval == 0 {
		config.BatchInterval = 2 * time.Second
	}
	if config.MaxTxPerAccountDuringRebase == 0 {
		config.MaxTxPerAccountDuringRebase = 5
	}
	if config.BlocksBeforeRebasingToThrottle == 0 {
		config.BlocksBeforeRebasingToThrottle = 10
	}
	
	return &TxManager{
		config:     config,
		txpool:     txpool,
		queue:      make(map[common.Address][]*types.Transaction),
		newTx:      make(chan struct{}, 1),
		accounts:   make(map[common.Address]*accountInfo),
		blockchain: blockchain,
		quit:       make(chan struct{}),
	}
}

// Start inicia o gerenciador de transações
func (tm *TxManager) Start() error {
	log.Info("Starting transaction manager with batching support")
	
	tm.wg.Add(1)
	go tm.loop()
	
	// Monitorar novos blocos para resetar contadores de transação
	tm.wg.Add(1)
	go tm.monitorBlocks()
	
	return nil
}

// Stop para o gerenciador de transações
func (tm *TxManager) Stop() {
	log.Info("Stopping transaction manager")
	close(tm.quit)
	tm.wg.Wait()
}

// AddTransaction enfileira uma transação para processamento
func (tm *TxManager) AddTransaction(tx *types.Transaction) error {
	sender, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
	if err != nil {
		return err
	}
	
	tm.queueMutex.Lock()
	defer tm.queueMutex.Unlock()
	
	// Adicionar à fila da conta
	tm.queue[sender] = append(tm.queue[sender], tx)
	
	// Sinalizar nova transação
	select {
	case tm.newTx <- struct{}{}:
	default:
	}
	
	return nil
}

// isNearRebasing verifica se estamos próximos de um bloco de rebasing
func (tm *TxManager) isNearRebasing() bool {
	if !tm.config.ThrottleNearRebasing {
		return false
	}
	
	currentBlock := tm.blockchain.CurrentBlock()
	if currentBlock == nil {
		return false
	}
	
	// Calcular quantos blocos faltam para o próximo rebasing
	blockNumber := currentBlock.Number.Uint64()
	blocksPerEpoch := rebase.BLOCKS_PER_EPOCH.Uint64()
	blocksUntilNextEpoch := blocksPerEpoch - (blockNumber % blocksPerEpoch)
	
	return blocksUntilNextEpoch <= uint64(tm.config.BlocksBeforeRebasingToThrottle)
}

// processQueues processa as filas de transações
func (tm *TxManager) processQueues() {
	tm.queueMutex.Lock()
	defer tm.queueMutex.Unlock()
	
	if len(tm.queue) == 0 {
		return
	}
	
	batch := make([]*types.Transaction, 0, tm.config.MaxBatchSize)
	batchSize := 0
	
	// Verificar se estamos próximos do rebasing
	nearRebasing := tm.isNearRebasing()
	maxTxPerAccount := tm.config.MaxBatchSize
	if nearRebasing {
		maxTxPerAccount = tm.config.MaxTxPerAccountDuringRebase
		log.Info("Throttling transactions due to approaching rebase block")
	}
	
	// Coletar transações de cada conta respeitando os limites
	for addr, txs := range tm.queue {
		if len(txs) == 0 {
			delete(tm.queue, addr)
			continue
		}
		
		// Inicializar informações da conta se necessário
		if _, exists := tm.accounts[addr]; !exists {
			nonce := tm.txpool.Nonce(addr)
			tm.accounts[addr] = &accountInfo{
				pendingNonce: nonce,
				txCount:      0,
			}
		}
		
		// Determinar quantas transações podemos processar desta conta
		accountInfo := tm.accounts[addr]
		txsToProcess := len(txs)
		if nearRebasing && txsToProcess > maxTxPerAccount-accountInfo.txCount {
			txsToProcess = maxTxPerAccount - accountInfo.txCount
			if txsToProcess <= 0 {
				continue // Já atingiu o limite para esta conta
			}
		}
		
		// Limitar ao tamanho máximo do batch
		if batchSize+txsToProcess > tm.config.MaxBatchSize {
			txsToProcess = tm.config.MaxBatchSize - batchSize
			if txsToProcess <= 0 {
				break // Batch cheio
			}
		}
		
		// Adicionar transações ao batch
		batch = append(batch, txs[:txsToProcess]...)
		batchSize += txsToProcess
		
		// Atualizar a fila da conta
		tm.queue[addr] = txs[txsToProcess:]
		
		// Incrementar contador de transações
		if nearRebasing {
			accountInfo.txCount += txsToProcess
		}
	}
	
	// Enviar batch para o pool de transações
	if len(batch) > 0 {
		errs := tm.txpool.AddRemotes(batch)
		
		// Log de erros
		for i, err := range errs {
			if err != nil {
				log.Warn("Failed to add transaction to pool", "tx", batch[i].Hash(), "err", err)
			}
		}
		
		log.Info("Processed transaction batch", "count", len(batch), "near_rebase", nearRebasing)
	}
}

// loop é a rotina principal do gerenciador
func (tm *TxManager) loop() {
	defer tm.wg.Done()
	
	ticker := time.NewTicker(tm.config.BatchInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-tm.newTx:
			tm.processQueues()
		case <-ticker.C:
			tm.processQueues()
		case <-tm.quit:
			return
		}
	}
}

// monitorBlocks monitora novos blocos para resetar contadores
func (tm *TxManager) monitorBlocks() {
	defer tm.wg.Done()
	
	events := make(chan core.ChainHeadEvent, 10)
	sub := tm.blockchain.SubscribeChainHeadEvent(events)
	defer sub.Unsubscribe()
	
	for {
		select {
		case <-events:
			// Resetar contadores de transações por conta no novo bloco
			tm.queueMutex.Lock()
			for addr, info := range tm.accounts {
				info.txCount = 0
				
				// Atualizar nonce pendente
				info.pendingNonce = tm.txpool.Nonce(addr)
			}
			tm.queueMutex.Unlock()
			
		case <-tm.quit:
			return
		}
	}
}