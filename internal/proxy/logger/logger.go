package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/shared/database"
	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
)

const (
	httpDataInputBufferSize int = 100
	httpDataCacheSize       int = 40
)

// Namespace value used for all UUIDv5 functions in database, for logger-related data.
const uuidNameSpace string = "61970c6a-6d09-4502-88fd-5ecff9150956"

// NewLogger returns a new, properly instantiated Logger object.
// Any errors returned should be considered fatal
func NewLogger(cfg *config.Config) (*Logger, error) {
	// Initialize basic values
	logger := &Logger{
		mu:            sync.RWMutex{},
		cfg:           cfg,
		enabled:       true,
		httpDataInput: make(chan *datatypes.HttpReqResp, httpDataInputBufferSize),
		httpDataCache: make([]*datatypes.HttpReqResp, 0, httpDataCacheSize),
	}

	// Get database connections
	dbConnPool, dbConnPoolErr := database.GetDbConnPool(cfg.DbConnString)
	if dbConnPoolErr != nil {
		return nil, fmt.Errorf("unable to get database connection pool: %w", dbConnPoolErr)
	}

	// Set database connection values
	logger.dbConnPool = dbConnPool

	return logger, nil
}

// Logger is the configuration object for the Logger plugin.
// A Logger object should *always* be instantiated via the NewLogger function.
type Logger struct {
	// mu is a RWMutex to control concurrent access.
	mu sync.RWMutex

	// enabled is true if the Logger plugin is enabled.
	enabled bool

	// dbConnPool is a database connection pool used for concurrency-safe database connections.
	dbConnPool *pgxpool.Pool

	// cfg is the configuration object for the web proxy.
	cfg *config.Config

	// httpDataInput is used to accept all HTTP request and response data to be logged to the database.
	httpDataInput chan *datatypes.HttpReqResp

	// httpDataCache is used to temporarily cache HTTP data before sending it to the database in a batch copy.
	httpDataCache []*datatypes.HttpReqResp
}

// Run will start the logger plugin.
// This function should be called in a goroutine, as it will block indefinitely, until an error is returned.
// Any errors returned should be considered fatal.
func (logger *Logger) Run() error {
	// Prepare an error channel for fatal errors
	fatalErrChan := make(chan error, 1)

	// Create a ticker for flushing out the local caches.
	// Use a random interval to prevent bottlenecks in the database by competing services.
	// The random time is anywhere between 40 and 120 seconds.
	cacheFlushTicker := time.NewTicker(time.Second * time.Duration(rand.Intn(80)+40))

	// Handle HTTP data sent to the logger, as well as any fatal errors received from its internal goroutines
	for {
		select {
		case err := <-fatalErrChan:
			// Flush the local cache to the database, then return the error
			logger.saveCacheToDb()
			logger.clearCache()
			return err
		case httpData := <-logger.httpDataInput:
			// Check that the http data is a logger target
			if !logger.cfg.IsTarget(httpData.ReferrerData.Referer.Host, httpData.Request.Url.Host) {
				continue
			}

			// Create a deep copy of the data, so we can safely modify it, as this same data is also
			// referenced elsewhere.
			data := httpData.DeepCopy()

			// Remove unwanted data from the HTTP data
			cleanReqRespData(&data)

			// Add the data to the cache
			logger.saveToCache(&data)

			// Save the data
			if !logger.cacheFull() {
				continue
			}

			// Save cache to the database
			logger.saveCacheToDb()

			// Clear the cache
			logger.clearCache()
		case <-cacheFlushTicker.C:
			// Save the cache to the database
			logger.saveCacheToDb()

			// Clear the cache again
			logger.clearCache()
		}
	}
}

// LogHttpData is used to send HTTP request and response data to the logger for processing.
func (logger *Logger) LogHttpData(httpData *datatypes.HttpReqResp) {
	logger.httpDataInput <- httpData
}

// saveToCache saves the given HTTP data to the local cache, which will eventually be sent to the database
// in a large batch transaction.
func (logger *Logger) saveToCache(httpData *datatypes.HttpReqResp) {
	logger.mu.Lock()
	defer logger.mu.Unlock()

	logger.httpDataCache = append(logger.httpDataCache, httpData)
}

// cacheFull returns true if the HTTP data cache is full, and ready to be flushed to the database.
func (logger *Logger) cacheFull() bool {
	logger.mu.RLock()
	defer logger.mu.RUnlock()

	return len(logger.httpDataCache) >= httpDataCacheSize-1
}

func (logger *Logger) clearCache() {
	logger.mu.Lock()
	defer logger.mu.Unlock()

	// Clear the cache, while keeping the allocated memory
	logger.httpDataCache = logger.httpDataCache[:0]
}

// saveCacheToDb saves the given HTTP request and response data to the database.
// All errors are logged by this function, as we have implemented a transaction rollback and retry
// mechanism that requires us not to return immediately with any errors, so the database transaction can
// attempt to retry.
// We are deliberately making a trade-off between speed and accuracy, so malformed data will simply be skipped,
// and a bad database connection simply results in all the data not being logged. Therefore, it is very important
// to watch for error logs from this function, as they will not stop the logger from working, but HTTP data may
// not be logged to the database as a result.
func (logger *Logger) saveCacheToDb() {
	ctx := context.Background()

	// Slices containing all the data we're going to copy into the database tables
	var inventoryInputRows [][]interface{}
	var apiHunterInputRows [][]interface{}

	// Lock the HTTP data cache
	logger.mu.RLock()
	defer logger.mu.RUnlock()

	// Create the data structure that we will copy into the temporary table
	for _, rr := range logger.httpDataCache {
		// Skip any ridiculously long URL paths (google search is prone to do this), as it will likely overflow the
		// maximum btree v4 index size of 2704 bytes.
		// We're only really concerned with the path, because the other parts of the btree index (scheme, host,
		// request method, and response code) are unlikely to ever come close to the maximum size.
		if len(rr.Request.Url.Path) > 1000 {
			continue
		}

		// Parse the query to get the parameters
		query, queryErr := url.ParseQuery(rr.Request.Url.RawQuery)
		if queryErr != nil {
			// Problem with data format; skip this HTTP data
			log.WithError(queryErr).WithField("url", rr.Request.Url.String()).Errorf("unable to parse URL query %q", rr.Request.Url.RawQuery)
			continue
		}

		// Request URL parameter keys
		var paramKeys []string
		for key := range query {
			if !utf8.ValidString(key) {
				continue
			}
			paramKeys = append(paramKeys, key)
		}
		if paramKeys == nil {
			// Ensure no nil parameters in database
			paramKeys = []string{""}
		}

		// Request URL parameter key values
		var paramKeyValues []string
		for key, values := range query {
			if !utf8.ValidString(key) {
				continue
			}
			for _, value := range values {
				if !utf8.ValidString(value) {
					continue
				}
				paramKeyValues = append(paramKeyValues, fmt.Sprintf("%s=%s", key, value))
			}
		}
		if paramKeyValues == nil {
			// Ensure no nil parameters in database
			paramKeyValues = []string{""}
		}

		// Request header keys
		var headerReqKeys []string
		for key := range rr.Request.Header {
			if !utf8.ValidString(key) {
				continue
			}
			headerReqKeys = append(headerReqKeys, key)
		}
		if headerReqKeys == nil {
			// Ensure no nil values in database
			headerReqKeys = []string{""}
		}

		// Request header key values
		var headerReqKeyValues []string
		for key := range rr.Request.Header {
			if !utf8.ValidString(key) {
				continue
			}
			for _, value := range rr.Request.Header.Values(key) {
				if !utf8.ValidString(value) {
					continue
				}
				headerReqKeyValues = append(headerReqKeyValues, fmt.Sprintf("%s: %s", key, value))
			}
		}
		if headerReqKeyValues == nil {
			// Ensure no nil values in database
			headerReqKeyValues = []string{""}
		}

		// Response header keys
		var headerRespKeys []string
		for key := range rr.Response.Header {
			if !utf8.ValidString(key) {
				continue
			}
			headerRespKeys = append(headerRespKeys, key)
		}
		if headerRespKeys == nil {
			// Ensure no nil values in database
			headerRespKeys = []string{""}
		}

		// Response header key values
		var headerRespKeyValues []string
		for key := range rr.Response.Header {
			if !utf8.ValidString(key) {
				continue
			}
			for _, value := range rr.Response.Header.Values(key) {
				if !utf8.ValidString(value) {
					continue
				}
				headerRespKeyValues = append(headerRespKeyValues, fmt.Sprintf("%s: %s", key, value))
			}
		}
		if headerRespKeyValues == nil {
			// Ensure no nil values in database
			headerRespKeyValues = []string{""}
		}

		// Cookie keys. Use a map to ensure we don't duplicate cookies
		// across requests and responses.
		cookieMap := map[string]bool{}
		for _, cookie := range rr.Request.Cookies {
			cookieMap[cookie.Name] = true
		}
		for _, cookie := range rr.Response.Cookies {
			cookieMap[cookie.Name] = true
		}
		// Delete empty keys
		delete(cookieMap, "")

		// Convert the map to a slice for inserting to the database
		var cookieKeys []string
		for cookie := range cookieMap {
			if !utf8.ValidString(cookie) {
				continue
			}
			cookieKeys = append(cookieKeys, cookie)
		}
		if cookieKeys == nil {
			// Ensure no nil values in database
			cookieKeys = []string{""}
		}

		// Cookie key values. Use a map to ensure we don't duplicate
		// cookies across requests and responses.
		cookieKeyValuesMap := map[string]bool{}
		for _, cookie := range rr.Request.Cookies {
			cookieKeyValuesMap[fmt.Sprintf("%s: %s", cookie.Name, cookie.String())] = true
		}
		for _, cookie := range rr.Response.Cookies {
			cookieKeyValuesMap[fmt.Sprintf("%s: %s", cookie.Name, cookie.String())] = true
		}
		// Delete empty keys
		delete(cookieKeyValuesMap, "")

		// Convert the map to a slice for inserting to the database
		var cookieKeyValues []string
		for cookie := range cookieKeyValuesMap {
			if !utf8.ValidString(cookie) {
				continue
			}
			cookieKeyValues = append(cookieKeyValues, cookie)
		}
		// Ensure no nil values in database
		if cookieKeyValues == nil {
			cookieKeyValues = []string{""}
		}

		// Append the values to the "data_logger" table input rows
		inventoryInputRows = append(inventoryInputRows, []interface{}{rr.Request.Url.Scheme, rr.Request.Url.Host, rr.Request.Url.Path, rr.Request.Timestamp, rr.Request.Method, paramKeys, headerReqKeys, headerRespKeys, cookieKeys, rr.Response.StatusCode, paramKeyValues, headerReqKeyValues, headerRespKeyValues, cookieKeyValues, rr.Request.Timestamp})

		// If we have any request or response body data, then we will add to the API Hunter input rows slice
		if len(rr.Request.BodyJson) > 0 || len(rr.Request.BodyText) > 0 || len(rr.Response.BodyJson) > 0 || len(rr.Response.BodyText) > 0 {
			// Change any empty JSON request or response bodies to an empty JSON object ("{}")
			if len(rr.Request.BodyJson) == 0 {
				rr.Request.BodyJson = json.RawMessage([]byte("{}"))
			}
			if len(rr.Response.BodyJson) == 0 {
				rr.Response.BodyJson = json.RawMessage([]byte("{}"))
			}

			// Add to the API Hunter input rows slice
			apiHunterInputRows = append(apiHunterInputRows, []interface{}{rr.Request.Url.Scheme, rr.Request.Url.Host, rr.Request.Url.Path, rr.Request.Method, rr.Request.BodyJson, rr.Request.BodyText, rr.Response.BodyJson, rr.Response.BodyText, rr.Response.StatusCode, rr.Request.Timestamp})
		}
	}

	// Perform the logger and API Hunter database transactions in goroutines
	var wg sync.WaitGroup

	// Log the inventory data
	if len(inventoryInputRows) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Handle transaction rollback with back-off and retry if unsuccessful.
			txOk := false
			retryCount := 0
			maxRetries := 4

			// BUG: The first row of the data_logger database is full of empty data.

			for ; retryCount < maxRetries && !txOk; retryCount++ {
				// Start the transaction
				tx, txErr := logger.dbConnPool.Begin(ctx)
				if txErr != nil {
					// This should never happen, unless the connection is broken or there is a context timeout.
					// Either way, transactions probably won't work after this anyway.
					log.WithError(txErr).Error("unable to start database transaction")
				}

				// Create a temporary table to copy the data into.
				// We will create a random name for the table, to prevent conflict if this function runs concurrently.
				// Yes, we will concatenate it into the SQL string, but given that there is no direct user input into this
				// random name, we do not have to worry about SQL injection.
				tmpTableName := fmt.Sprintf("tmp_%d_%d", time.Now().UnixNano(), rand.Intn(9999))
				sqlQueryTmpTableCreate := fmt.Sprintf(`CREATE TEMPORARY TABLE %s (url_scheme TEXT DEFAULT ''::TEXT NOT NULL, url_host TEXT NOT NULL, url_path TEXT DEFAULT ''::TEXT NOT NULL, date_found TIMESTAMP WITH TIME ZONE NOT NULL, req_method TEXT DEFAULT ''::TEXT NOT NULL, param_keys TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_keys_req TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_keys_resp TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, cookie_keys TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, resp_code INT DEFAULT 0 NOT NULL, param_key_vals TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_key_vals_req TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_key_vals_resp TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, cookie_key_vals TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, last_seen timestamp with time zone not null) ON COMMIT DROP;`, tmpTableName)
				if _, tmpTableCreateErr := tx.Exec(ctx, sqlQueryTmpTableCreate); tmpTableCreateErr != nil {
					log.WithError(tmpTableCreateErr).Error("unable to create temporary database table")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Copy the data into the temporary table using postgresql's COPY FROM semantics
				copyCount, copyErr := tx.CopyFrom(ctx, pgx.Identifier{tmpTableName}, []string{"url_scheme", "url_host", "url_path", "date_found", "req_method", "param_keys", "header_keys_req", "header_keys_resp", "cookie_keys", "resp_code", "param_key_vals", "header_key_vals_req", "header_key_vals_resp", "cookie_key_vals", "last_seen"}, pgx.CopyFromRows(inventoryInputRows))
				if copyErr != nil {
					log.WithError(copyErr).Error("unable to copy data into temporary database table for inventory data")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}
				if int(copyCount) != len(inventoryInputRows) {
					log.Errorf("expected to copy %d rows, but only copied %d rows into temporary database table", len(inventoryInputRows), copyCount)
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Copy the data from the temporary table into the permanent table
				_, insertErr := tx.Exec(ctx, fmt.Sprintf("INSERT INTO data_logger (url_scheme, url_host, url_path, date_found, req_method, param_keys, header_keys_req, header_keys_resp, cookie_keys, resp_code, param_key_vals, header_key_vals_req, header_key_vals_resp, cookie_key_vals, last_seen) SELECT url_scheme, url_host, url_path, date_found, req_method, param_keys, header_keys_req, header_keys_resp, cookie_keys, resp_code, param_key_vals, header_key_vals_req, header_key_vals_resp, cookie_key_vals, last_seen FROM %s ON CONFLICT DO NOTHING;", tmpTableName))
				if insertErr != nil {
					log.WithError(insertErr).Error("unable to insert temporary table data into database")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Append the new values from the temporary table into the arrays on the existing
				// table.
				// To do this, we update all rows where the url scheme, host, path, and
				// request type match between the inventory and temporary table,
				// concatenating the arrays together, un-nesting them, then joining them
				// back together with the "distinct" select clause in the array_agg
				// function. This has the result of updating all arrays to only
				// include distinct elements.
				_, updateArraysErr := tx.Exec(ctx, fmt.Sprintf(`UPDATE data_logger AS inv
		SET param_keys = (
				SELECT array_agg(distinct vals) FROM unnest(inv.param_keys || tmp.param_keys) vals
			),
			header_keys_req = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_keys_req || tmp.header_keys_req) vals
			),
			header_keys_resp = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_keys_resp || tmp.header_keys_resp) vals
			),
			cookie_keys = (
				SELECT array_agg(distinct vals) FROM unnest(inv.cookie_keys || tmp.cookie_keys) vals
			),
			param_key_vals = (
				SELECT array_agg(distinct vals) FROM unnest(inv.param_key_vals || tmp.param_key_vals) vals
			),
			header_key_vals_req = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_key_vals_req || tmp.header_key_vals_req) vals
			),
			header_key_vals_resp = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_key_vals_resp || tmp.header_key_vals_resp) vals
			),
			cookie_key_vals = (
				SELECT array_agg(distinct vals) FROM unnest(inv.cookie_key_vals || tmp.cookie_key_vals) vals
			)
		FROM %s AS tmp
		WHERE tmp.url_scheme = inv.url_scheme AND tmp.url_host = inv.url_host AND tmp.url_path = inv.url_path AND tmp.req_method = inv.req_method AND tmp.resp_code = inv.resp_code;`, tmpTableName))
				if updateArraysErr != nil {
					log.WithError(updateArraysErr).Error("unable to append data from temporary table into inventory arrays")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Update the "last seen" time for all entries in the database
				_, updateTimesErr := tx.Exec(ctx, fmt.Sprintf(`update data_logger as i set last_seen = (select tmp.last_seen from %s as tmp where i.url_scheme = tmp.url_scheme and i.url_host = tmp.url_host and i.url_path = tmp.url_path and i.req_method = tmp.req_method and i.resp_code = tmp.resp_code order by last_seen limit 1) from %s as tmp where i.url_scheme = tmp.url_scheme and i.url_host = tmp.url_host and i.url_path = tmp.url_path and i.req_method = tmp.req_method and i.resp_code = tmp.resp_code;`, tmpTableName, tmpTableName))
				if updateTimesErr != nil {
					log.WithError(updateTimesErr).Error("unable to update 'last_seen' time in inventory table from temporary table")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Commit the transaction
				if commitErr := tx.Commit(ctx); commitErr != nil {
					log.WithError(commitErr).Error("unable to commit transaction to database")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				txOk = true
			}
		}()
	}

	// Log the API Hunter data
	if len(apiHunterInputRows) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			txOk := false
			retryCount := 0
			maxRetries := 4

			for ; retryCount < maxRetries && !txOk; retryCount++ {
				// Start the transaction
				tx, txErr := logger.dbConnPool.Begin(ctx)
				if txErr != nil {
					log.WithError(txErr).Error("unable to start database transaction")
					continue
				}

				tmpTableName := fmt.Sprintf("tmp_api_hunter_%d_%d", time.Now().UnixNano(), rand.Intn(9999))
				sqlQueryTmpTableCreate := fmt.Sprintf(`
					CREATE TEMPORARY TABLE %s (
						url_scheme      text                     not null,
						url_host        text                     not null,
						url_path        text                     not null,
						req_method      text                     not null,
						req_body_json   jsonb,
						req_body_plain  text,
						resp_body_json  jsonb,
						resp_body_plain text,
						resp_code       integer default 0        not null,
						timestamp       timestamp with time zone not null
					) ON COMMIT DROP;
				`, tmpTableName)

				if _, tmpTableCreateErr := tx.Exec(ctx, sqlQueryTmpTableCreate); tmpTableCreateErr != nil {
					log.WithError(tmpTableCreateErr).Error("unable to create temporary database table")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Copy the data into the temporary table
				copyCount, copyErr := tx.CopyFrom(
					ctx,
					pgx.Identifier{tmpTableName},
					[]string{"url_scheme", "url_host", "url_path", "req_method", "req_body_json", "req_body_plain", "resp_body_json", "resp_body_plain", "resp_code", "timestamp"},
					pgx.CopyFromRows(apiHunterInputRows),
				)

				if copyErr != nil {
					log.WithError(copyErr).Error("unable to copy data into temporary database table for API hunter data")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				if int(copyCount) != len(apiHunterInputRows) {
					log.Errorf("expected to copy %d rows, but only copied %d rows into temporary database table", len(apiHunterInputRows), copyCount)
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				// Copy the data from the temporary table into the actual data_api_hunter table
				_, insertErr := tx.Exec(ctx, fmt.Sprintf(`
            INSERT INTO data_api_hunter (url_scheme, url_host, url_path, req_method, req_body_json, req_body_plain, resp_body_json, resp_body_plain, resp_code, timestamp)
            SELECT url_scheme, url_host, url_path, req_method, req_body_json, req_body_plain, resp_body_json, resp_body_plain, resp_code, timestamp
            FROM %s
            ON CONFLICT DO NOTHING;
        `, tmpTableName))

				if insertErr != nil {
					log.WithError(insertErr).Error("unable to insert temporary table data into data_api_hunter database")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				if commitErr := tx.Commit(ctx); commitErr != nil {
					log.WithError(commitErr).Error("unable to commit transaction to database")
					if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
						log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
					}
					continue
				}

				txOk = true
			}
		}()
	}

	wg.Wait()

	return
}

// saveCacheToDbPrivacyEnhanced saves the given HTTP request and response data to the database.
// It is designed to enhance privacy by storing keys only, and not values for parameters, headers, and cookies.
// All errors are logged by this function, as we have implemented a transaction rollback and retry
// mechanism that requires us not to return immediately with any errors, so the database transaction can
// attempt to retry.
// We are deliberately making a trade-off between speed and accuracy, so malformed data will simply be skipped,
// and a bad database connection simply results in all the data not being logged. Therefore, it is very important
// to watch for error logs from this function, as they will not stop the logger from working, but HTTP data may
// not be logged to the database as a result.
func (logger *Logger) saveCacheToDbPrivacyEnhanced() {
	ctx := context.Background()

	// Slices containing all the data we're going to copy into the database tables
	var inventoryInputRows [][]interface{}
	var httpReqBodyJsonInputRows [][]interface{}
	var httpRespBodyJsonInputRows [][]interface{}
	var httpRespBodyHtmlInputRows [][]interface{}

	// Lock the HTTP data cache
	logger.mu.RLock()
	defer logger.mu.RUnlock()

	// Create the data structure that we will copy into the temporary table
	for _, rr := range logger.httpDataCache {
		// Skip any ridiculously long URL paths (google search is prone to do this), as it will likely overflow the
		// maximum btree v4 index size of 2704 bytes.
		// We're only really concerned with the path, because the other parts of the btree index (scheme, host,
		// request method, and response code) are unlikely to ever come close to the maximum size.
		if len(rr.Request.Url.Path) > 1000 {
			continue
		}

		// Parse the query to get the parameters
		query, queryErr := url.ParseQuery(rr.Request.Url.RawQuery)
		if queryErr != nil {
			// Problem with data format; skip this HTTP data
			log.WithError(queryErr).WithField("url", rr.Request.Url.String()).Errorf("unable to parse URL query %q", rr.Request.Url.RawQuery)
			continue
		}

		// Request URL parameter keys
		var paramKeys []string
		for key := range query {
			if !utf8.ValidString(key) {
				continue
			}
			paramKeys = append(paramKeys, key)
		}
		if paramKeys == nil {
			// Ensure no nil parameters in database
			paramKeys = []string{""}
		}

		// Request URL parameter key values
		paramKeyValues := []string{""}

		// Request header keys
		var headerReqKeys []string
		for key := range rr.Request.Header {
			if !utf8.ValidString(key) {
				continue
			}
			headerReqKeys = append(headerReqKeys, key)
		}
		if headerReqKeys == nil {
			// Ensure no nil values in database
			headerReqKeys = []string{""}
		}

		// Request header key values
		headerReqKeyValues := []string{""}

		// Response header keys
		var headerRespKeys []string
		for key := range rr.Response.Header {
			if !utf8.ValidString(key) {
				continue
			}
			headerRespKeys = append(headerRespKeys, key)
		}
		if headerRespKeys == nil {
			// Ensure no nil values in database
			headerRespKeys = []string{""}
		}

		// Response header key values
		var headerRespKeyValues []string
		for key := range rr.Response.Header {
			// Save the "Server" header value
			// if key == "Server" {
			// 	headerRespKeyValues = append(headerRespKeyValues, fmt.Sprintf("%s: %s", key, rr.Response.Header.Get(key)))
			// }

			// Don't save the cookies
			if key == "Set-Cookie" || key == "Set-Cookie2" {
				continue
			}

			if !utf8.ValidString(key) || !utf8.ValidString(rr.Response.Header.Get(key)) {
				continue
			}

			headerRespKeyValues = append(headerRespKeyValues, fmt.Sprintf("%s: %s", key, rr.Response.Header.Get(key)))
		}
		if headerRespKeyValues == nil {
			// Ensure no nil values in database
			headerRespKeyValues = []string{""}
		}

		// Cookie keys. Use a map to ensure we don't duplicate cookies
		// across requests and responses.
		cookieMap := map[string]bool{}
		for _, cookie := range rr.Request.Cookies {
			cookieMap[cookie.Name] = true
		}
		for _, cookie := range rr.Response.Cookies {
			cookieMap[cookie.Name] = true
		}
		// Delete empty keys
		delete(cookieMap, "")

		// Convert the map to a slice for inserting to the database
		var cookieKeys []string
		for cookie := range cookieMap {
			if !utf8.ValidString(cookie) {
				continue
			}
			cookieKeys = append(cookieKeys, cookie)
		}
		if cookieKeys == nil {
			// Ensure no nil values in database
			cookieKeys = []string{""}
		}

		// Cookie key values.
		cookieKeyValues := []string{""}

		// Append the values to the "data_logger" table input rows
		inventoryInputRows = append(inventoryInputRows, []interface{}{rr.Request.Url.Scheme, rr.Request.Url.Host, rr.Request.Url.Path, rr.Request.Timestamp, rr.Request.Method, paramKeys, headerReqKeys, headerRespKeys, cookieKeys, rr.Response.StatusCode, paramKeyValues, headerReqKeyValues, headerRespKeyValues, cookieKeyValues, rr.Request.Timestamp})

		// Check for JSON request data
		if len(rr.Request.BodyJson) > 0 {
			// Append to the "http_request_body_json" table input rows
			httpReqBodyJsonInputRows = append(httpReqBodyJsonInputRows, []interface{}{rr.Request.Url.Scheme, rr.Request.Url.Host, rr.Request.Url.Path, rr.Request.Method, rr.Request.BodyJson, rr.Response.StatusCode, rr.Request.Timestamp})
		}

		// Check for JSON response data
		if len(rr.Response.BodyJson) > 0 {
			// Append to the "http_request_body_json" table input rows
			httpRespBodyJsonInputRows = append(httpRespBodyJsonInputRows, []interface{}{rr.Request.Url.Scheme, rr.Request.Url.Host, rr.Request.Url.Path, rr.Request.Method, rr.Response.BodyJson, rr.Response.StatusCode, rr.Request.Timestamp})
		}
	}

	// Handle transaction rollback with back-off and retry if unsuccessful.
	txOk := false
	retryCount := 0
	maxRetries := 4

	// BUG: The first row of the data_logger database is full of empty data.

	for ; retryCount < maxRetries && !txOk; retryCount++ {
		// Start the transaction
		tx, txErr := logger.dbConnPool.Begin(ctx)
		if txErr != nil {
			// This should never happen, unless the connection is broken or there is a context timeout.
			// Either way, transactions probably won't work after this anyway.
			log.WithError(txErr).Error("unable to start database transaction")
		}

		// Create a temporary table to copy the data into.
		// We will create a random name for the table, to prevent conflict if this function runs concurrently.
		// Yes, we will concatenate it into the SQL string, but given that there is no direct user input into this
		// random name, we do not have to worry about SQL injection.
		tmpTableName := fmt.Sprintf("tmp_%d_%d", time.Now().UnixNano(), rand.Intn(9999))
		sqlQueryTmpTableCreate := fmt.Sprintf(`CREATE TEMPORARY TABLE %s (url_scheme TEXT DEFAULT ''::TEXT NOT NULL, url_host TEXT NOT NULL, url_path TEXT DEFAULT ''::TEXT NOT NULL, date_found TIMESTAMP WITH TIME ZONE NOT NULL, req_method TEXT DEFAULT ''::TEXT NOT NULL, param_keys TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_keys_req TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_keys_resp TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, cookie_keys TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, resp_code INT DEFAULT 0 NOT NULL, param_key_vals TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_key_vals_req TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, header_key_vals_resp TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, cookie_key_vals TEXT[] DEFAULT '{}'::TEXT[] NOT NULL, last_seen timestamp with time zone not null) ON COMMIT DROP;`, tmpTableName)
		if _, tmpTableCreateErr := tx.Exec(ctx, sqlQueryTmpTableCreate); tmpTableCreateErr != nil {
			log.WithError(tmpTableCreateErr).Error("unable to create temporary database table")
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}

		// Copy the data into the temporary table using postgresql's COPY FROM semantics
		copyCount, copyErr := tx.CopyFrom(ctx, pgx.Identifier{tmpTableName}, []string{"url_scheme", "url_host", "url_path", "date_found", "req_method", "param_keys", "header_keys_req", "header_keys_resp", "cookie_keys", "resp_code", "param_key_vals", "header_key_vals_req", "header_key_vals_resp", "cookie_key_vals", "last_seen"}, pgx.CopyFromRows(inventoryInputRows))
		if copyErr != nil {
			log.WithError(copyErr).Error("unable to copy data into temporary database table")
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}
		if int(copyCount) != len(inventoryInputRows) {
			log.Errorf("expected to copy %d rows, but only copied %d rows into temporary database table", len(inventoryInputRows), copyCount)
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}

		// Copy the data from the temporary table into the permanent table
		_, insertErr := tx.Exec(ctx, fmt.Sprintf("INSERT INTO data_logger (url_scheme, url_host, url_path, date_found, req_method, param_keys, header_keys_req, header_keys_resp, cookie_keys, resp_code, param_key_vals, header_key_vals_req, header_key_vals_resp, cookie_key_vals, last_seen) SELECT url_scheme, url_host, url_path, date_found, req_method, param_keys, header_keys_req, header_keys_resp, cookie_keys, resp_code, param_key_vals, header_key_vals_req, header_key_vals_resp, cookie_key_vals, last_seen FROM %s ON CONFLICT DO NOTHING;", tmpTableName))
		if insertErr != nil {
			log.WithError(insertErr).Error("unable to insert temporary table data into database")
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}

		// Append the new values from the temporary table into the arrays on the existing
		// table.
		// To do this, we update all rows where the url scheme, host, path, and
		// request type match between the inventory and temporary table,
		// concatenating the arrays together, un-nesting them, then joining them
		// back together with the "distinct" select clause in the array_agg
		// function. This has the result of updating all arrays to only
		// include distinct elements.
		_, updateArraysErr := tx.Exec(ctx, fmt.Sprintf(`UPDATE data_logger AS inv
		SET param_keys = (
				SELECT array_agg(distinct vals) FROM unnest(inv.param_keys || tmp.param_keys) vals
			),
			header_keys_req = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_keys_req || tmp.header_keys_req) vals
			),
			header_keys_resp = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_keys_resp || tmp.header_keys_resp) vals
			),
			cookie_keys = (
				SELECT array_agg(distinct vals) FROM unnest(inv.cookie_keys || tmp.cookie_keys) vals
			),
			param_key_vals = (
				SELECT array_agg(distinct vals) FROM unnest(inv.param_key_vals || tmp.param_key_vals) vals
			),
			header_key_vals_req = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_key_vals_req || tmp.header_key_vals_req) vals
			),
			header_key_vals_resp = (
				SELECT array_agg(distinct vals) FROM unnest(inv.header_key_vals_resp || tmp.header_key_vals_resp) vals
			),
			cookie_key_vals = (
				SELECT array_agg(distinct vals) FROM unnest(inv.cookie_key_vals || tmp.cookie_key_vals) vals
			)
		FROM %s AS tmp
		WHERE tmp.url_scheme = inv.url_scheme AND tmp.url_host = inv.url_host AND tmp.url_path = inv.url_path AND tmp.req_method = inv.req_method AND tmp.resp_code = inv.resp_code;`, tmpTableName))
		if updateArraysErr != nil {
			log.WithError(updateArraysErr).Error("unable to append data from temporary table into inventory arrays")
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}

		// Update the "last seen" time for all entries in the database
		_, updateTimesErr := tx.Exec(ctx, fmt.Sprintf(`update data_logger as i set last_seen = (select tmp.last_seen from %s as tmp where i.url_scheme = tmp.url_scheme and i.url_host = tmp.url_host and i.url_path = tmp.url_path and i.req_method = tmp.req_method and i.resp_code = tmp.resp_code order by last_seen limit 1) from %s as tmp where i.url_scheme = tmp.url_scheme and i.url_host = tmp.url_host and i.url_path = tmp.url_path and i.req_method = tmp.req_method and i.resp_code = tmp.resp_code;`, tmpTableName, tmpTableName))
		if updateTimesErr != nil {
			log.WithError(updateTimesErr).Error("unable to update 'last_seen' time in inventory table from temporary table")
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}

		// Add JSON request data
		if len(httpReqBodyJsonInputRows) > 0 {
			reqJsonCopyCount, reqJsonCopyErr := tx.CopyFrom(ctx, pgx.Identifier{"http_request_body_json"}, []string{"url_scheme", "url_host", "url_path", "req_method", "req_body", "resp_code", "timestamp"}, pgx.CopyFromRows(httpReqBodyJsonInputRows))
			if reqJsonCopyErr != nil {
				log.WithError(reqJsonCopyErr).Error("unable to copy JSON request body data into database")
				if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
					log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
				}
				continue
			}
			if int(reqJsonCopyCount) != len(httpReqBodyJsonInputRows) {
				log.Errorf("expected to copy %d rows, but only copied %d rows into JSON request body table", len(httpReqBodyJsonInputRows), reqJsonCopyCount)
				if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
					log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
				}
				continue
			}
		}

		// Add JSON response data
		if len(httpRespBodyJsonInputRows) > 0 {
			respJsonCopyCount, respJsonCopyErr := tx.CopyFrom(ctx, pgx.Identifier{"http_response_body_json"}, []string{"url_scheme", "url_host", "url_path", "req_method", "resp_body", "resp_code", "timestamp"}, pgx.CopyFromRows(httpRespBodyJsonInputRows))
			if respJsonCopyErr != nil {
				log.WithError(respJsonCopyErr).Error("unable to copy JSON response body data into database")
				if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
					log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
				}
				continue
			}
			if int(respJsonCopyCount) != len(httpRespBodyJsonInputRows) {
				log.Errorf("expected to copy %d rows, but only copied %d rows into JSON response body table", len(httpRespBodyJsonInputRows), respJsonCopyCount)
				if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
					log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
				}
				continue
			}
		}

		// Add HTML response data
		if len(httpRespBodyHtmlInputRows) > 0 {
			respHtmlCopyCount, respHtmlCopyErr := tx.CopyFrom(ctx, pgx.Identifier{"http_response_body_html"}, []string{"url_scheme", "url_host", "url_path", "req_method", "resp_body", "resp_code", "timestamp"}, pgx.CopyFromRows(httpRespBodyHtmlInputRows))
			if respHtmlCopyErr != nil {
				log.WithError(respHtmlCopyErr).Error("unable to copy HTML response body data into database")
				if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
					log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
				}
				continue
			}
			if int(respHtmlCopyCount) != len(httpRespBodyHtmlInputRows) {
				log.Errorf("expected to copy %d rows, but only copied %d rows into HTML response body table", len(httpRespBodyHtmlInputRows), respHtmlCopyCount)
				if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
					log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
				}
				continue
			}
		}

		// Commit the transaction
		if commitErr := tx.Commit(ctx); commitErr != nil {
			log.WithError(commitErr).Error("unable to commit transaction to database")
			if rollbackErr := rollbackAndBackoff(tx); rollbackErr != nil {
				log.WithError(rollbackErr).Error("problem with transaction rollback and backoff")
			}
			continue
		}

		txOk = true
	}

	return
}

// rollbackAndBackoff is a helper function that attempts to roll back a transaction, and then sleep before returning.
func rollbackAndBackoff(tx pgx.Tx) (err error) {
	// Rollback the transaction
	if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil {
		err = fmt.Errorf("unable to rollback database transaction: %w", rollbackErr)
	}

	// Wait a given backoff period
	time.Sleep(time.Second * 2)

	return
}

// LoggerData holds data returned from the Logger plugin's database table that is being returned to a client.
type LoggerData struct {
	URLScheme string

	URLHost string

	URLPath string

	DateFound time.Time

	LastSeen time.Time

	ReqMethod string

	RespCode int

	ParamKeyValues []string

	HeaderKeyValuesReq []string

	HeaderKeyValuesResp []string

	CookieKeyValues []string
}

// getData returns the logger data associated with the given target filter.
func (logger *Logger) getData(df *datatypes.DataFilter) ([]*LoggerData, error) {
	// TODO: Fill this function out for use in the API, when needed.

	return nil, nil
}

// DomainData holds domain data returned from the Logger plugin's database table that is being returned to a client.
type DomainData struct {
	Domain    string    `json:"domain"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// getAllHosts returns all distinct hosts logged by the Logger.
func (logger *Logger) getAllHosts() ([]*DomainData, error) {
	ctx := context.Background()

	// Fetch the hosts from the database
	sqlSelectDomainData := `select url_host, min(date_found) as first, max(last_seen) as last from data_logger where url_host != '' group by url_host order by url_host;`
	rows, dbSelectErr := logger.dbConnPool.Query(ctx, sqlSelectDomainData)
	if dbSelectErr != nil {
		return nil, fmt.Errorf("unable to get domain data from database: %w", dbSelectErr)
	}

	// Ensure the rows are closed; it's safe to call Close multiple times
	defer rows.Close()

	// Iterate through the domain data
	domainDataList := make([]*DomainData, 0)
	for rows.Next() {
		var domainData DomainData
		if scanErr := rows.Scan(&domainData.Domain, &domainData.FirstSeen, &domainData.LastSeen); scanErr != nil {
			return nil, fmt.Errorf("unable to scan domain data from database: %w", scanErr)
		}

		// Add the domain data to the list
		domainDataList = append(domainDataList, &domainData)
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return domainDataList, nil
}

// PathData holds path data returned from the Logger plugin's database table that is being returned to a client.
type PathData struct {
	Path          string    `json:"path"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	ResponseCodes []int     `json:"response_codes"`
	URLSchemes    []string  `json:"url_schemes"`
}

// getFullPathDataForDomain returns all distinct paths logged by the Logger for the given domain, including their response
// codes, protocols (URL schemes), and when they were each first seen and last seen.
func (logger *Logger) getFullPathDataForDomain(domain string) ([]*PathData, error) {
	ctx := context.Background()

	// Fetch the paths from the database
	sqlSelectPathData := `select url_path, array_agg(distinct url_scheme), array_agg(distinct resp_code), min(date_found) as first, max(last_seen) as last from data_logger where url_host = $1 group by url_path order by url_path;`
	rows, dbSelectErr := logger.dbConnPool.Query(ctx, sqlSelectPathData, domain)
	if dbSelectErr != nil {
		return nil, fmt.Errorf("unable to get path data from database: %w", dbSelectErr)
	}

	// Ensure the rows are closed; it's safe to call Close multiple times
	defer rows.Close()

	// Iterate through the path data
	pathDataList := make([]*PathData, 0)
	for rows.Next() {
		var pathData PathData
		if scanErr := rows.Scan(&pathData.Path, &pathData.URLSchemes, &pathData.ResponseCodes, &pathData.FirstSeen, &pathData.LastSeen); scanErr != nil {
			return nil, fmt.Errorf("unable to scan path data from database: %w", scanErr)
		}

		// Add the path data to the list
		pathDataList = append(pathDataList, &pathData)
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return pathDataList, nil
}

// getPathTreeForDomain returns a tree of paths logged by the Logger for the given domain.
func (logger *Logger) getPathTreeForDomain(domain string) (*ArrayPathTree, error) {
	ctx := context.Background()

	// Fetch the paths from the database
	sqlSelectPaths := `select url_path from data_logger where url_host = $1 order by url_path;`
	rows, dbSelectErr := logger.dbConnPool.Query(ctx, sqlSelectPaths, domain)
	if dbSelectErr != nil {
		return nil, fmt.Errorf("unable to get path data from database: %w", dbSelectErr)
	}

	// Ensure the rows are closed; it's safe to call Close multiple times
	defer rows.Close()

	// Iterate through the path data
	pathDataList := make([]string, 0)
	for rows.Next() {
		var pathData string
		if scanErr := rows.Scan(&pathData); scanErr != nil {
			return nil, fmt.Errorf("unable to scan path data from database: %w", scanErr)
		}

		// Add the path data to the list
		pathDataList = append(pathDataList, pathData)
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	// Build the path tree
	pathTree := newPathTree()
	for _, path := range pathDataList {
		pathTree.addPath(path)
	}

	// Convert the path tree to an array path tree
	arrayPathTree := pathTree.toArrayPathTree()

	return arrayPathTree, nil
}

// PathTree is a tree of paths for a domain.
type PathTree struct {
	// The path segment for this node
	PathSegment string `json:"path_segment"`

	// The children of this node
	Children map[string]*PathTree `json:"children"`
}

// newPathTree returns a new PathTree.
func newPathTree() *PathTree {
	return &PathTree{
		PathSegment: "/",
		Children:    make(map[string]*PathTree),
	}
}

// addPath adds the given path to the PathTree.
func (pathTree *PathTree) addPath(path string) {
	// Split the path into segments
	pathSegments := strings.Split(path, "/")

	// Add the path segments to the tree
	currentNode := pathTree
	for _, pathSegment := range pathSegments {
		// If the path segment is empty, then it's a root path
		if pathSegment == "" {
			continue
		}

		// Prepend path segments with a "/" to avoid name collisions in the final tree output
		pathSegment = "/" + pathSegment

		// If the child node doesn't exist, create it
		if _, ok := currentNode.Children[pathSegment]; !ok {
			currentNode.Children[pathSegment] = &PathTree{
				PathSegment: pathSegment,
				Children:    make(map[string]*PathTree),
			}
		}

		// Move to the child node
		currentNode = currentNode.Children[pathSegment]
	}
}

// ArrayPathTree uses an array to store the children of the path tree instead of a map, which is useful for
// parsing with d3.js after being converted to JSON.
type ArrayPathTree struct {
	// The path segment for this node
	PathSegment string `json:"path_segment"`

	// The children of this node
	Children []*ArrayPathTree `json:"children,omitempty"`
}

// toArrayPathTree converts a PathTree to an ArrayPathTree.
func (pathTree *PathTree) toArrayPathTree() *ArrayPathTree {
	// Convert the children to an array
	children := make([]*ArrayPathTree, 0)
	for _, child := range pathTree.Children {
		children = append(children, child.toArrayPathTree())
	}

	return &ArrayPathTree{
		PathSegment: pathTree.PathSegment,
		Children:    children,
	}
}

// KeyValuePairData holds key-value pair data returned from the Logger plugin's database table that is being returned
// to a client.
type KeyValuePairData struct {
	KeyValue string `json:"key_value"`
}

// getParametersForPath returns all parameter key-value pairs logged by the Logger for the given domain,
// path, and (optional) response codes.
func (logger *Logger) getParametersForPath(domain string, path string, responseCodesFilter []int) ([]KeyValuePairData, error) {
	ctx := context.Background()

	// Fetch the parameters from the database
	var rows pgx.Rows
	var dbSelectErr error
	if len(responseCodesFilter) == 0 {
		// Do not filter by response codes
		sqlSelectParameterData := `with param_query as (select url_host, url_path, unnest(param_key_vals) as unnested from data_logger) select distinct unnested from param_query where url_host = $1 and url_path = $2 and unnested != '';`
		rows, dbSelectErr = logger.dbConnPool.Query(ctx, sqlSelectParameterData, domain, path)
		if dbSelectErr != nil {
			return nil, fmt.Errorf("unable to get parameter data from database: %w", dbSelectErr)
		}
	} else {
		// Filter by response codes
		sqlSelectParameterData := `with param_query as (select url_host, url_path, resp_code, unnest(param_key_vals) as unnested from data_logger) select distinct unnested from param_query where url_host = $1 and url_path = $2 and unnested != '' and resp_code = any($3);`
		rows, dbSelectErr = logger.dbConnPool.Query(ctx, sqlSelectParameterData, domain, path, responseCodesFilter)
		if dbSelectErr != nil {
			return nil, fmt.Errorf("unable to get parameter data from database: %w", dbSelectErr)
		}
	}

	// Ensure the rows are closed; it's safe to call Close multiple times
	defer rows.Close()

	// Iterate through the parameter data
	parameterDataList := make([]KeyValuePairData, 0)
	for rows.Next() {
		var parameterData KeyValuePairData
		if scanErr := rows.Scan(&parameterData.KeyValue); scanErr != nil {
			return nil, fmt.Errorf("unable to scan parameter data from database: %w", scanErr)
		}

		// Add the parameter data to the list
		parameterDataList = append(parameterDataList, parameterData)
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return parameterDataList, nil
}

// getRequestHeadersForPath returns all request header key-value pairs logged by the Logger for the given domain,
// path, and (optional) response codes.
func (logger *Logger) getRequestHeadersForPath(domain string, path string, responseCodesFilter []int) ([]KeyValuePairData, error) {
	ctx := context.Background()

	// Fetch the headers from the database
	var rows pgx.Rows
	var dbSelectErr error
	if len(responseCodesFilter) == 0 {
		// Do not filter by response codes
		sqlSelectHeaderData := `with header_query as (select url_host, url_path, unnest(header_key_vals_req) as unnested from data_logger) select distinct unnested from header_query where url_host = $1 and url_path = $2 and unnested != '';`
		rows, dbSelectErr = logger.dbConnPool.Query(ctx, sqlSelectHeaderData, domain, path)
		if dbSelectErr != nil {
			return nil, fmt.Errorf("unable to get request header data from database: %w", dbSelectErr)
		}
	} else {
		// Filter by response codes
		sqlSelectHeaderData := `with header_query as (select url_host, url_path, resp_code, unnest(header_key_vals_req) as unnested from data_logger) select distinct unnested from header_query where url_host = $1 and url_path = $2 and unnested != '' and resp_code = any($3);`
		rows, dbSelectErr = logger.dbConnPool.Query(ctx, sqlSelectHeaderData, domain, path, responseCodesFilter)
		if dbSelectErr != nil {
			return nil, fmt.Errorf("unable to get request header data from database: %w", dbSelectErr)
		}
	}

	// Ensure the rows are closed; it's safe to call Close multiple times
	defer rows.Close()

	// Iterate through the header data
	headerDataList := make([]KeyValuePairData, 0)
	for rows.Next() {
		var headerData KeyValuePairData
		if scanErr := rows.Scan(&headerData.KeyValue); scanErr != nil {
			return nil, fmt.Errorf("unable to scan request header data from database: %w", scanErr)
		}

		// Add the header data to the list
		headerDataList = append(headerDataList, headerData)
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return headerDataList, nil
}

// getResponseHeadersForPath returns all response header key-value pairs logged by the Logger for the given domain, path, and (optional) response codes.
func (logger *Logger) getResponseHeadersForPath(domain string, path string, responseCodesFilter []int) ([]KeyValuePairData, error) {
	ctx := context.Background()

	// Fetch the headers from the database
	var rows pgx.Rows
	var dbSelectErr error
	if len(responseCodesFilter) == 0 {
		// Do not filter by response codes
		sqlSelectHeaderData := `with header_query as (select url_host, url_path, unnest(header_key_vals_resp) as unnested from data_logger) select distinct unnested from header_query where url_host = $1 and url_path = $2 and unnested != '';`
		rows, dbSelectErr = logger.dbConnPool.Query(ctx, sqlSelectHeaderData, domain, path)
		if dbSelectErr != nil {
			return nil, fmt.Errorf("unable to get response header data from database: %w", dbSelectErr)
		}
	} else {
		// Filter by response codes
		sqlSelectHeaderData := `with header_query as (select url_host, url_path, resp_code, unnest(header_key_vals_resp) as unnested from data_logger) select distinct unnested from header_query where url_host = $1 and url_path = $2 and unnested != '' and resp_code = any($3);`
		rows, dbSelectErr = logger.dbConnPool.Query(ctx, sqlSelectHeaderData, domain, path, responseCodesFilter)
		if dbSelectErr != nil {
			return nil, fmt.Errorf("unable to get response header data from database: %w", dbSelectErr)
		}
	}

	// Ensure the rows are closed; it's safe to call Close multiple times
	defer rows.Close()

	// Iterate through the header data
	headerDataList := make([]KeyValuePairData, 0)
	for rows.Next() {
		var headerData KeyValuePairData
		if scanErr := rows.Scan(&headerData.KeyValue); scanErr != nil {
			return nil, fmt.Errorf("unable to scan response header data from database: %w", scanErr)
		}

		// Add the header data to the list
		headerDataList = append(headerDataList, headerData)
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return headerDataList, nil
}

// cleanReqRespData cleans the given HTTP request and response object of any data that we don't want to log.
func cleanReqRespData(reqResp *datatypes.HttpReqResp) {
	// Request headers
	reqResp.Request.Header.Del("Cache-Control")
	reqResp.Request.Header.Del("Connection")
	reqResp.Request.Header.Del("Content-Length")
	reqResp.Request.Header.Del("Date")
	reqResp.Request.Header.Del("Pragma")
	reqResp.Request.Header.Del("Range")

	// Response headers
	reqResp.Response.Header.Del("Age")
	reqResp.Response.Header.Del("Cache-Control")
	reqResp.Response.Header.Del("Connection")
	reqResp.Response.Header.Del("Content-Length")
	reqResp.Response.Header.Del("Date")
	reqResp.Response.Header.Del("Etag")
	reqResp.Response.Header.Del("Expires")
	reqResp.Response.Header.Del("Last-Modified")
	reqResp.Response.Header.Del("Pragma")
	reqResp.Response.Header.Del("Transfer-Encoding")
	reqResp.Response.Header.Del("Vary")
	reqResp.Response.Header.Del("X-Content-Type-Options")
	reqResp.Response.Header.Del("X-XSS-Protection")
	reqResp.Response.Header.Del("Content-Range")
	// reqResp.Response.Header.Del("Set-Cookie")
	// reqResp.Response.Header.Del("Set-Cookie2")
	reqResp.Response.Header.Del("X-Request-ID")
	reqResp.Response.Header.Del("Content-Encoding")
}
