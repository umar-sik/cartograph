package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/analyzer/vectorize"
)

var vectorVersion string

func init() {
	// Set the vector version as today's date, using decimal format
	vectorVersion = fmt.Sprintf("%d", time.Now().Unix())
}

// CreateVectors creates vectors for all data in the database.
func (a *Analyzer) CreateVectors() error {
	ctx := context.Background()

	// Channel to store vectors for the database, along with the other data needed to insert them
	vectorChan := make(chan *vectorDbInsertData, 1000)

	// Get a count of the total number of vectors that will be created
	var totalVectorCount int
	if vectorCountQueryErr := a.dbConnPool.QueryRow(ctx, `WITH cte AS (
			SELECT url_scheme, url_host, url_path
			FROM data_logger
			WHERE url_scheme <> '' AND url_host <> '' AND url_path <> ''
			GROUP BY url_scheme, url_host, url_path
		)
		SELECT COUNT(*) FROM cte;`).Scan(&totalVectorCount); vectorCountQueryErr != nil {
		return fmt.Errorf("unable to get total vector count: %w", vectorCountQueryErr)
	}

	// Start a transaction
	tx, txErr := a.dbConnPool.Begin(ctx)
	if txErr != nil {
		return fmt.Errorf("unable to start database transaction: %w", txErr)
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		err := tx.Rollback(ctx)
		if err != nil {
			log.WithError(err).Error("unable to rollback transaction")
		}
	}(tx, ctx) // nolint: errcheck

	// Delete existing vectors table data
	if _, deleteErr := tx.Exec(ctx, `DELETE FROM vectors WHERE TRUE;`); deleteErr != nil {
		return fmt.Errorf("unable to delete existing vectors table data: %w", deleteErr)
	}

	// Query the data using a cursor, with a chunk size of 100
	cursorQuery := `DECLARE vector_cursor CURSOR FOR WITH unnested_data AS (
		SELECT url_scheme,
			   url_host,
			   url_path,
			   req_method,
			   resp_code,
			   UNNEST(header_keys_req)      AS header_key_req,
			   UNNEST(header_key_vals_req)  AS header_key_val_req,
			   UNNEST(header_keys_resp)     AS header_key_resp,
			   UNNEST(header_key_vals_resp) AS header_key_val_resp,
			   UNNEST(param_keys)           AS param_key,
			   UNNEST(cookie_keys)          AS cookie_key
		FROM data_logger)
		SELECT url_scheme,
			   url_host,
			   url_path,
			   COALESCE(ARRAY_AGG(DISTINCT req_method), ARRAY []::text[])                                                          AS unique_req_methods,
			   COALESCE(ARRAY_AGG(DISTINCT resp_code), ARRAY []::integer[])                                                        AS unique_resp_codes,
			   COALESCE(ARRAY_AGG(DISTINCT header_key_req) FILTER (WHERE header_key_req IS NOT NULL), ARRAY []::text[])             AS unique_req_header_keys,
			   COALESCE(ARRAY_AGG(DISTINCT header_key_resp) FILTER (WHERE header_key_resp IS NOT NULL), ARRAY []::text[])           AS unique_resp_header_keys,
			   COALESCE(ARRAY_AGG(DISTINCT param_key) FILTER (WHERE param_key IS NOT NULL), ARRAY []::text[])                       AS unique_param_keys,
			   COALESCE(ARRAY_AGG(DISTINCT cookie_key) FILTER (WHERE cookie_key IS NOT NULL), ARRAY []::text[])                     AS unique_cookie_keys,
			   COALESCE(ARRAY_AGG(DISTINCT header_key_val_resp) FILTER (WHERE header_key_val_resp LIKE 'Server:%'), ARRAY []::text[]) AS unique_server_header_vals,
			   COALESCE(ARRAY_AGG(DISTINCT header_key_val_req) FILTER (WHERE header_key_req = 'Content-Type'), ARRAY []::text[])    AS content_type_req_vals,
			   COALESCE(ARRAY_AGG(DISTINCT header_key_val_resp) FILTER (WHERE header_key_resp = 'Content-Type'), ARRAY []::text[])   AS content_type_resp_vals
		FROM unnested_data
		WHERE url_scheme <> ''
		  AND url_host <> ''
		  AND url_path <> ''
		GROUP BY url_scheme,
				 url_host,
				 url_path;`
	_, txExecErr := tx.Exec(ctx, cursorQuery)
	if txExecErr != nil {
		return fmt.Errorf("unable to execute cursor query: %w", txExecErr)
	}

	currentVectorCount := 0

	// Fetch chunks of data from the cursor in a loop until there is no more data
	for {
		// Fetch the data from the cursor
		cursorRows, cursorRowsErr := tx.Query(ctx, "FETCH 100 FROM vector_cursor")
		if cursorRowsErr != nil {
			return fmt.Errorf("unable to fetch data from cursor: %w", cursorRowsErr)
		}
		log.Debugf("Processing vectors %d-%d out of %d", currentVectorCount, currentVectorCount+100, totalVectorCount)
		currentVectorCount += 100

		// Process the data
		cursorDataErr := a.processCursorRows(cursorRows, vectorChan)
		cursorRows.Close()

		// Save the vectors to the database
		for i := len(vectorChan); i > 0; i-- {
			vectorData := <-vectorChan
			if _, saveErr := tx.Exec(ctx, `INSERT INTO vectors (url_scheme,
																		  url_host,
																		  url_path,
																		  vector,
																		  vector_version)
														VALUES ($1, $2, $3, $4, $5);`,
				vectorData.URLScheme,
				vectorData.URLHost,
				vectorData.URLPath,
				vectorData.Vector,
				vectorVersion); saveErr != nil {
				return fmt.Errorf("unable to save vectors to database: %w", saveErr)
			}
		}

		// Check for errors
		if cursorDataErr == pgx.ErrNoRows {
			break
		}
		if cursorDataErr != nil {
			return fmt.Errorf("unable to process cursor rows: %w", cursorDataErr)
		}

		// Check if we've processed all the vectors
		if currentVectorCount >= totalVectorCount {
			break
		}
	}

	// Commit the transaction
	txCommitErr := tx.Commit(ctx)
	if txCommitErr != nil {
		return fmt.Errorf("unable to commit transaction: %w", txCommitErr)
	}

	// Close the vector channel to indicate that we've finished vectorizing
	close(vectorChan)

	// Count how many vectors were created
	var vectorCount int
	if err := a.dbConnPool.QueryRow(ctx, `SELECT COUNT(*) FROM vectors;`).Scan(&vectorCount); err != nil {
		return fmt.Errorf("unable to count vectors: %w", err)
	}
	log.Infoln("Created", vectorCount, "vectors")

	// Count the number of features in the vectors (vector length).
	// We do this by selecting only one vector and counting the number of elements in the vector array.
	var vectorLength int
	if err := a.dbConnPool.QueryRow(ctx, `SELECT ARRAY_LENGTH(vector, 1) FROM vectors LIMIT 1;`).Scan(&vectorLength); err != nil {
		return fmt.Errorf("unable to count vector lengths: %w", err)
	}
	log.Infoln("Vector length:", vectorLength)

	return nil
}

func (a *Analyzer) processCursorRows(cursorRows pgx.Rows, vectorChan chan<- *vectorDbInsertData) error {
	// Iterate over the cursor rows
	for cursorRows.Next() {
		// Scan the data into a vectorInputData struct
		// log.Debug("Scanning cursor row")
		var inputData vectorInputData
		if scanErr := cursorRows.Scan(
			&inputData.URLScheme,
			&inputData.URLHost,
			&inputData.URLPath,
			&inputData.RequestMethods,
			&inputData.ResponseCodes,
			&inputData.RequestHeaderKeys,
			&inputData.ResponseHeaderKeys,
			&inputData.URLParameterKeys,
			&inputData.CookieKeys,
			&inputData.ServerHeaders,
			// &inputData.CSPHeaders,
			&inputData.RequestContentTypes,
			&inputData.ResponseContentTypes,
		); scanErr != nil {
			return fmt.Errorf("unable to scan cursor row: %w", scanErr)
		}

		// Vectorize the data
		vector := a.vectorize(&inputData)

		// Send the vector to the channel, so it can be inserted back into the database
		vectorChan <- &vectorDbInsertData{
			URLScheme: inputData.URLScheme,
			URLHost:   inputData.URLHost,
			URLPath:   inputData.URLPath,
			Vector:    vector,
		}
	}

	return cursorRows.Err()
}

// vectorDbInsertData contains the data needed to insert a vector into the database.
type vectorDbInsertData struct {
	URLScheme string
	URLHost   string
	URLPath   string
	Vector    []float32
}

// vectorInputData contains the data needed to vectorize an HTTP request/response.
type vectorInputData struct {
	URLScheme          string
	URLHost            string
	URLPath            string
	RequestHeaderKeys  []string
	ResponseHeaderKeys []string
	// CSPHeaders         []string
	URLParameterKeys     []string
	CookieKeys           []string
	RequestMethods       []string
	ResponseCodes        []int
	ServerHeaders        []string
	RequestContentTypes  []string
	ResponseContentTypes []string
}

// vectorize converts the given HTTP request/response to a vector for machine learning analysis.
func (a *Analyzer) vectorize(inputData *vectorInputData) []float32 {
	// Vectorize HTTP header keys
	vectorHeaderKeys := vectorize.HeaderKeys(inputData.RequestHeaderKeys, inputData.ResponseHeaderKeys)

	// Vectorize CSP header
	// vectorCSPHeader := vectorize.CspHeader(inputData.CSPHeaders)

	// Vectorize URL parameter keys
	vectorURLParamKeys := vectorize.UrlParamKeys(inputData.URLParameterKeys)

	// Vectorize cookie keys
	vectorCookieKeys := vectorize.CookieKeys(inputData.CookieKeys)

	// Vectorize the HTTP request method
	vectorRequestMethod := vectorize.RequestMethod(inputData.RequestMethods)

	// Vectorize the HTTP response code
	vectorResponseCode := vectorize.ResponseCode(inputData.ResponseCodes)

	// Vectorize the server header value
	vectorServerHeader := vectorize.ServerHeader(inputData.ServerHeaders)

	// NOTE: We removed IP address vectorization, as it is of a different measurement type than the other vectors
	// 	(e.g. it is a 32-bit integer, while the others are 1-bit booleans), so it would skew the results heavily.
	// Vectorize the IP address
	// vectorIP, vectorIPErr := vectors.Ip(httpData)
	// if vectorIPErr != nil {
	// 	log.WithError(vectorIPErr).Error("error vectorizing IP address")
	// }

	// Vectorize the request and response content types
	vectorContentTypes := vectorize.ContentTypes(inputData.RequestContentTypes, inputData.ResponseContentTypes)

	// Join all the vectors together
	// vector := append(vectorHeaderKeys, vectorCSPHeader...)
	vector := append(vectorHeaderKeys, vectorURLParamKeys...)
	vector = append(vector, vectorCookieKeys...)
	vector = append(vector, vectorRequestMethod...)
	vector = append(vector, vectorResponseCode...)
	vector = append(vector, vectorServerHeader...)
	// if vectorIPErr != nil {
	// 	vector = append(vector, vectorIP...)
	// }
	vector = append(vector, vectorContentTypes...)

	return vector
}

// generateVectors generates seemingly valid HTTP request/response vectors for testing purposes.
func (a *Analyzer) generateVectors(numVectors int) [][]float32 {
	vectors := make([][]float32, numVectors)

	for i := 0; i < numVectors; i++ {
		// Generate header key vector
		headerKeyVector := vectorize.GenerateHeaderKeysVector()

		// Generate CSP header vector
		// cspHeaderVector := vectorize.GenerateCSPVector()

		// Generate URL parameter key vector
		urlParamKeyVector := vectorize.GenerateUrlParamKeysVector()

		// Generate cookie key vector
		cookieKeyVector := vectorize.GenerateCookieKeysVector()

		// Generate request method vector
		requestMethodVector := vectorize.GenerateRequestMethodVector()

		// Generate response code vector
		responseCodeVector := vectorize.GenerateResponseCodeVector()

		// Generate server header vector
		serverHeaderVector := vectorize.GenerateServerHeaderVector()

		// Generate content types vector
		contentTypesVector := vectorize.GenerateContentTypesVector()

		// Join all the vectors together
		// vector := append(headerKeyVector, cspHeaderVector...)
		vector := append(headerKeyVector, urlParamKeyVector...)
		vector = append(vector, cookieKeyVector...)
		vector = append(vector, requestMethodVector...)
		vector = append(vector, responseCodeVector...)
		vector = append(vector, serverHeaderVector...)
		vector = append(vector, contentTypesVector...)

		vectors[i] = vector
	}

	return vectors
}
