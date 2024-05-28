package analyzer

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/shared/database"
	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
)

const (
	corpusDataBufferSize int = 100
	corpusDataCacheSize  int = 40
)

// Namespace value used for all UUIDv5 functions in database, for analyzer-related data.
const uuidNameSpace string = "bddba772-b75f-4d0c-8f24-545e03bae467"

// NewAnalyzer returns a new analyzer object using the given configuration.
//
// Any errors returned should be considered fatal.
func NewAnalyzer(cfg *config.Config) (*Analyzer, error) {
	// Create a new analyzer object
	analyzer := &Analyzer{
		mu:              sync.RWMutex{},
		enabled:         true,
		training:        cfg.TrainingMode,
		corpusDataInput: make(chan *datatypes.HttpReqResp, corpusDataBufferSize),
		corpusDataCache: make([]*datatypes.CorpusData, 0, corpusDataCacheSize),
	}

	// Get database connections
	dbConnPool, dbConnPoolErr := database.GetDbConnPool(cfg.DbConnString)
	if dbConnPoolErr != nil {
		return nil, fmt.Errorf("unable to get database connection pool: %w", dbConnPoolErr)
	}
	listenDbConn, listenDbConnErr := database.GetDbConn(cfg.DbConnString)
	if listenDbConnErr != nil {
		return nil, fmt.Errorf("unable to get listen database connection: %w", listenDbConnErr)
	}

	// Set database connection values
	analyzer.dbConnPool = dbConnPool
	analyzer.listenDbConn = listenDbConn

	return analyzer, nil
}

// Analyzer is the main object for the analyzer plugin.
type Analyzer struct {
	// mu is a RWMutex to control concurrent access.
	mu sync.RWMutex

	// enabled is true if the Mapper plugin is enabled.
	enabled bool

	// training is true if the Mapper plugin is in training mode.
	training bool

	// dbConnPool is a database connection pool used for concurrency-safe database connections; mostly used
	// for handling API calls.
	dbConnPool *pgxpool.Pool

	// listenDbConn is a single database connection, used to listen for config updates from the database,
	// allowing for a distributed deployment of the web proxy.
	listenDbConn *pgx.Conn

	// corpusDataInput is used to accept corpus data that will be saved to the database for training.
	corpusDataInput chan *datatypes.HttpReqResp

	// corpusDataCache is used to temporarily cache corpus data before sending it to the database in a batch copy.
	corpusDataCache []*datatypes.CorpusData
}

// Run runs the analyzer plugin.
// Any errors returned should be considered fatal.
func (a *Analyzer) Run() error {
	// Create a ticker for flushing out the local caches.
	// Use a random interval to prevent bottlenecks in the database by competing services.
	// The random time is anywhere between 40 and 120 seconds.
	cacheFlushTicker := time.NewTicker(time.Duration(rand.Intn(80)+40) * time.Second)

	// Handle referred data sent to the analyzer
	for {
		select {
		case httpReqResp := <-a.corpusDataInput:
			// Make a deep copy of the http request/response data, so we can safely modify it,
			// as this same data is referenced elsewhere.
			data := httpReqResp.DeepCopy()

			// Convert to proper corpus data type
			corpusData := datatypes.CorpusDataFromReqResp(&data)

			// Add the corpus data to the cache
			a.saveToCorpusCache(corpusData)

			// If the cache is full, flush it to the database, then clear the cache
			if len(a.corpusDataCache) >= corpusDataCacheSize {
				a.saveCorpusCacheToDatabase()
				a.clearCorpusCache()
			}
		case <-cacheFlushTicker.C:
			// Flush the cache to the database, then clear the cache
			a.saveCorpusCacheToDatabase()
			a.clearCorpusCache()
		}
	}
}
