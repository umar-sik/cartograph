package mapper

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/shared/database"
	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

const (
	referredDataBufferSize int = 100
	referredDataCacheSize  int = 40
)

// NewMapper returns a new mapper object using the given configuration.
//
// Any errors returned should be considered fatal.
func NewMapper(cfg *config.Config) (*Mapper, error) {
	// Create a new mapper object
	mapper := &Mapper{
		mu:                     sync.RWMutex{},
		cfg:                    cfg,
		enabled:                true,
		referredDataInput:      make(chan *datatypes.ReferrerData, referredDataBufferSize),
		referredDataCache:      make([]*datatypes.ReferrerData, 0, referredDataCacheSize),
		mapperScriptName:       "mapper.js",
		mapperWorkerScriptName: "mapper-worker.js",
	}

	// Get database connections
	dbConnPool, dbConnPoolErr := database.GetDbConnPool(cfg.DbConnString)
	if dbConnPoolErr != nil {
		return nil, fmt.Errorf("unable to get database connection pool: %w", dbConnPoolErr)
	}
	insertDbConn, insertDbConnErr := database.GetDbConn(cfg.DbConnString)
	if insertDbConnErr != nil {
		return nil, fmt.Errorf("unable to get insert database connection: %w", insertDbConnErr)
	}

	// Set database connection values
	mapper.dbConnPool = dbConnPool
	mapper.insertDbConn = insertDbConn

	// Load the mapper JavaScript files from disk
	if loadScriptsErr := mapper.loadScripts(cfg.MapperScriptDir); loadScriptsErr != nil {
		return nil, fmt.Errorf("unable to load mapper scripts: %w", loadScriptsErr)
	}

	return mapper, nil
}

// Mapper is the main object for the mapper plugin.
type Mapper struct {
	// mu is a RWMutex to control concurrent access.
	mu sync.RWMutex

	// enabled is true if the Mapper plugin is enabled.
	enabled bool

	// cfg is the configuration for the program.
	cfg *config.Config

	// dbConnPool is a database connection pool used for concurrency-safe database connections; mostly used
	// for handling API calls.
	dbConnPool *pgxpool.Pool

	// insertDbConn is a single database connection, used to insert data into the database (which happens serially
	// from this plugin).
	insertDbConn *pgx.Conn

	// referredDataInput is used to accept link data that will be logged to the database.
	referredDataInput chan *datatypes.ReferrerData

	// referredDataCache is used to temporarily cache link data before sending it to the database in a batch copy.
	referredDataCache []*datatypes.ReferrerData

	// MapperScript is a JavaScript file that is injected onto browser pages to find and save URLs found on the page.
	MapperScript []byte

	// MapperScriptName is the name of the JavaScript file that is injected onto browser pages to find and save
	// URLs found on the page.
	mapperScriptName string

	// MapperWorkerScriptName is the name of the web worker JavaScript file that sends the discovered URLs to the
	// mapper plugin asynchronously, so as not to block the main thread.
	mapperWorkerScriptName string

	// MapperWorkerScript is a web worker JavaScript file that sends the discovered URLs to the mapper plugin
	// asynchronously, so as not to block the main thread.
	MapperWorkerScript []byte
}

// Run runs the mapper plugin.
// Any errors returned should be considered fatal.
func (m *Mapper) Run() error {
	// Create a ticker for flushing out the local caches.
	// Use a random interval to prevent bottlenecks in the database by competing services.
	// The random time is anywhere between 40 and 120 seconds.
	cacheFlushTicker := time.NewTicker(time.Duration(rand.Intn(80)+40) * time.Second)

	// Handle referred data sent to the mapper
	for {
		select {
		case referredData := <-m.referredDataInput:
			// Check that the referred data is a mapper target
			if !m.cfg.IsTarget(referredData.Referer.Host, referredData.Destination.Host) {
				continue
			}

			// Add the referred data to the cache
			m.saveToCache(referredData)

			// If the cache is full, flush it to the database, then clear the cache
			if len(m.referredDataCache) >= referredDataCacheSize {
				m.saveCacheToDatabase()
				m.clearCache()
			}
		case <-cacheFlushTicker.C:
			// Flush the cache to the database, then clear the cache
			m.saveCacheToDatabase()
			m.clearCache()
		}
	}
}

// LogReferredData is used to send a referred data object to the mapper plugin for processing.
func (m *Mapper) LogReferredData(referredData *datatypes.ReferrerData) {
	// Check if enabled first
	if !m.Enabled() {
		return
	}
	m.referredDataInput <- referredData
}

// saveToCache saves the given referred data to the cache, which will eventually be saved to the database in a batch.
func (m *Mapper) saveToCache(referredData *datatypes.ReferrerData) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.referredDataCache = append(m.referredDataCache, referredData)
}

// cacheFull returns true if the cache is full.
func (m *Mapper) cacheFull() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.referredDataCache) >= referredDataCacheSize-1
}

// clearCache clears the cache.
func (m *Mapper) clearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear the cache, while keeping the allocated memory
	m.referredDataCache = m.referredDataCache[:0]
}

// saveCacheToDatabase saves the cache to the database.
// All errors are logged by this function, but for sake of speed over accuracy, there is currently no retry
// mechanism for any individual row being added.
func (m *Mapper) saveCacheToDatabase() {
	ctx := context.Background()

	// Lock the mutex, so we can safely access the cache
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Save the cache to the database, one element at a time
	for _, referredData := range m.referredDataCache {
		// Skip any ridiculously long URL paths in the source or destination (google search is prone to do this), as
		// it will likely overflow the maximum btree v4 index size of 2704 bytes.
		// We're only really concerned with the path, because the other parts of the btree index (source and
		// destination scheme and host) are unlikely to ever come close to the maximum size.
		if len(referredData.Referer.Path) > 1000 || len(referredData.Destination.Path) > 1000 {
			continue
		}

		if _, insertErr := m.insertDbConn.Exec(ctx, `INSERT INTO data_mapper (referer_scheme, referer_host, referer_path, destination_scheme, destination_host, destination_path, first_seen, last_seen) VALUES ($1, $2, $3, $4, $5, $6, $7, $7) ON CONFLICT ON CONSTRAINT data_mapper_pk DO UPDATE SET last_seen = $7;`, referredData.Referer.Scheme, referredData.Referer.Host, referredData.Referer.Path, referredData.Destination.Scheme, referredData.Destination.Host, referredData.Destination.Path, referredData.Timestamp); insertErr != nil {
			log.WithError(insertErr).WithFields(log.Fields{
				"referer":     referredData.Referer.String(),
				"destination": referredData.Destination.String(),
			}).Error("unable to insert referred data into database")
		}
	}
}

// loadScripts loads the mapper script from the given directory and saves the bytes to the mapper plugin.
func (m *Mapper) loadScripts(directory string) error {
	// Load the mapper script (mapper.js) from the directory and save to the mapper plugin

	// Open the mapper script file
	mapperScriptFile, openMapperScriptErr := os.Open(filepath.Join(directory, "mapper.js"))
	if openMapperScriptErr != nil {
		return fmt.Errorf("unable to open mapper script file: %w", openMapperScriptErr)
	}
	defer func() {
		if closeErr := mapperScriptFile.Close(); closeErr != nil {
			log.WithError(closeErr).Error("unable to close mapper script file")
		}
	}()

	// Read the mapper script file
	mapperScriptBytes, readMapperScriptFileErr := io.ReadAll(mapperScriptFile)
	if readMapperScriptFileErr != nil {
		return fmt.Errorf("unable to read mapper script file: %w", readMapperScriptFileErr)
	}

	// Save the mapper script to the mapper plugin
	m.MapperScript = mapperScriptBytes

	// Load the mapper web worker script (mapper-worker.js) from the directory and save to the mapper plugin

	// Open the mapper web worker script file
	mapperWorkerScriptFile, openMapperWorkerScriptErr := os.Open(filepath.Join(directory, "mapper-worker.js"))
	if openMapperWorkerScriptErr != nil {
		return fmt.Errorf("unable to open mapper web worker script file: %w", openMapperWorkerScriptErr)
	}
	defer func() {
		if closeErr := mapperWorkerScriptFile.Close(); closeErr != nil {
			log.WithError(closeErr).Error("unable to close mapper web worker script file")
		}
	}()

	// Read the mapper web worker script file
	mapperWorkerScriptBytes, readMapperWorkerScriptFileErr := io.ReadAll(mapperWorkerScriptFile)
	if readMapperWorkerScriptFileErr != nil {
		return fmt.Errorf("unable to read mapper web worker script file: %w", readMapperWorkerScriptFileErr)
	}

	// Save the mapper web worker script to the mapper plugin
	m.MapperWorkerScript = mapperWorkerScriptBytes

	return nil
}

// Enabled returns true if the mapper plugin is enabled.
func (m *Mapper) Enabled() bool {
	return m.enabled
}

// InjectMapperScript injects the mapper script into the <head> field of the given HTTP response.
// If an error is returned, JavaScript was not successfully injected into the response.
func (m *Mapper) InjectMapperScript(response *http.Response, mapperData *datatypes.ReferrerData) error {
	// Only inject if the mapper plugin is enabled
	if !m.enabled {
		return nil
	}

	if response.Body == http.NoBody {
		// This shouldn't happen with an HTML response content-type, but just in case...
		return nil
	}

	// Check that this is for a valid target
	if !m.cfg.IsTarget(mapperData.Referer.Host, mapperData.Destination.Host) {
		return nil
	}

	// Read response body
	respBody, bodyCopy, readErr := internalHttp.ReadBody(response.Body)
	response.Body = bodyCopy
	if readErr != nil {
		return fmt.Errorf("unable to read response body: %w", readErr)
	}

	// Odd edge case, but it's happened
	if len(respBody) == 0 {
		return nil
	}

	switch strings.ToLower(response.Header.Get("content-encoding")) {
	// No compression
	case "":
		break
	// Gzip compression
	case "gzip":
		// Decode response body
		var decodeErr error
		respBody, decodeErr = internalHttp.DecodeGzip(respBody)
		if decodeErr != nil {
			return fmt.Errorf("unable to gzip-decode response body: %w", decodeErr)
		}
	case "br":
		// Decode response body
		var decodeErr error
		respBody, decodeErr = internalHttp.DecodeBrotli(respBody)
		if decodeErr != nil {
			return fmt.Errorf("unable to brotli-decode response body: %w", decodeErr)
		}
	case "deflate":
		// Decode response body
		var decodeErr error
		respBody, decodeErr = internalHttp.DecodeDeflate(respBody)
		if decodeErr != nil {
			return fmt.Errorf("unable to deflate-decode response body: %w", decodeErr)
		}
	default:
		return fmt.Errorf("unsupported content-encoding in response: %s", response.Header.Get("content-encoding"))
	}

	// Prepare the mapper script tag to inject into the response
	jsHeadInject := fmt.Sprintf(`<script type="text/javascript" src=%q"></script>`, m.mapperScriptName)

	// Find the head section of the HTML document within the first 1000 bytes (or the entire body, whichever is
	// smaller)
	headIndex := bytes.Index(respBody[:min(len(respBody), 1000)], []byte("<head>"))
	if headIndex == -1 {
		// Check for variations of the <head> tag to inject into
		headIndex = bytes.Index(respBody[:min(len(respBody), 1000)], []byte("<HEAD>"))
		if headIndex == -1 {
			// "head" tag not found, so we can't inject.
			// In many cases, this is because the response is not HTML, so we'll just ignore it.
			return nil
		}
	}
	// Create a new byte slice to hold the new response body
	newBody := make([]byte, 0, len(respBody)+len(jsHeadInject))
	// Copy over the response body up to and including the <head> tag
	newBody = append(newBody, respBody[:headIndex+len("<head>")]...)
	// Append the script elements after the <head> tag
	newBody = append(newBody, []byte(jsHeadInject)...)
	// Add the rest of the response body back on
	newBody = append(newBody, respBody[headIndex+len("<head>"):]...)
	// Replace the response body with the new one
	respBody = newBody

	// Save updated response body
	response.Body = io.NopCloser(bytes.NewReader(respBody))

	// Remove the "Content-Security-Policy" header, if present, to allow the injection of scripts
	response.Header.Del("Content-Security-Policy")

	// Modify headers
	response.ContentLength = int64(len(respBody))
	response.Header.Set("content-length", fmt.Sprintf("%d", len(respBody)))
	response.Header.Set("content-type", "text/html; charset=utf-8")
	response.Header.Del("content-encoding") // sending it uncompressed

	return nil
}

// GetMapperScriptName returns the name of the mapper script file.
func (m *Mapper) GetMapperScriptName() string {
	return m.mapperScriptName
}

// GetMapperWorkerScriptName returns the name of the mapper web worker script file.
func (m *Mapper) GetMapperWorkerScriptName() string {
	return m.mapperWorkerScriptName
}
