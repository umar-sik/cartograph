package injector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/shared/database"
	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

// Namespace value used for all UUIDv5 functions in database, for Injector-related data.
const uuidNameSpace string = "42761e3d-c100-45f9-8f15-3cc8227f34d8"

// NewInjector returns a new, properly instantiated Injector object.
// Any errors returned should be considered fatal.
func NewInjector(cfg *config.Config) (*Injector, error) {
	// Initialize basic values
	injector := &Injector{
		mu:         sync.RWMutex{},
		cfg:        cfg,
		enabled:    true,
		scriptURLs: make(map[string]string),
	}

	// Get database connections
	dbConnPool, dbConnPoolErr := database.GetDbConnPool(cfg.DbConnString)
	if dbConnPoolErr != nil {
		return nil, fmt.Errorf("unable to get database connection pool: %w", dbConnPoolErr)
	}
	dbConn, dbConnErr := database.GetDbConn(cfg.DbConnString)
	if dbConnErr != nil {
		return nil, fmt.Errorf("unable to get database connection: %w", dbConnErr)
	}

	// Set database connection values
	injector.dbConnPool = dbConnPool
	injector.listenDbConn = dbConn

	// Attempt to set from the database
	if configSetErr := injector.setFromDb(); configSetErr != nil {
		return nil, fmt.Errorf("unable to set the Injector configuration from the database: %w", configSetErr)
	}

	return injector, nil
}

// Injector is the configuration object for the Injector plugin.
// An Injector object should *always* be instantiated via the NewInjector method.
type Injector struct {
	// RWMutex to control concurrent access
	mu sync.RWMutex

	// enabled is true if the Injector plugin is enabled.
	enabled bool

	// cfg is the configuration object for the program.
	cfg *config.Config

	// scriptURLs holds all the script URLs used by the injector, mapped to a UUIDv5 key.
	scriptURLs map[string]string

	// Database connection pool used for concurrency-safe connections.
	dbConnPool *pgxpool.Pool

	// Single database connection, used to listen for updates from the database,
	// which we then use to update our injector in an event-driven manner.
	listenDbConn *pgx.Conn
}

// Run runs all background operations for the injector plugin; namely, the database monitor that checks
// for configuration changes and updates the local configuration to match.
// Any errors returned should be considered fatal.
func (injector *Injector) Run() error {
	// Prepare an error channel for fatal errors
	fatalErrChan := make(chan error, 1)

	// Start the database monitor
	go func() {
		if err := injector.dbMonitor(context.Background()); err != nil {
			fatalErrChan <- fmt.Errorf("problem with the injector database monitor: %w", err)
		}
	}()

	return <-fatalErrChan
}

// dbMonitor listens for updates to the injector from the database, and updates the local injector
// whenever a notification is received.
// This method runs as a continuous listener, so it will block until an error is returned.
func (injector *Injector) dbMonitor(ctx context.Context) error {
	// Establish the listener
	listenChannel := "injector_script_urls_channel"
	_, listenErr := injector.listenDbConn.Exec(ctx, "listen "+listenChannel)
	if listenErr != nil {
		return fmt.Errorf("unable to listen to channel %q: %w", listenChannel, listenErr)
	}

	// Wait for notifications
	for {
		notification, notificationErr := injector.listenDbConn.WaitForNotification(ctx)
		if notificationErr != nil {
			return fmt.Errorf("problem with the %q channel notification listener: %w", listenChannel, notificationErr)
		}

		// Determine the field that was updated
		changeType, scriptPayload, separatorFound := strings.Cut(notification.Payload, ",")
		if !separatorFound {
			return fmt.Errorf("improperly formatted update notification payload sent from database: %q", notification.Payload)
		}

		// Get the script URL and ID
		scriptId, scriptUrl, scriptSeparatorFound := strings.Cut(scriptPayload, ":")
		if !scriptSeparatorFound {
			return fmt.Errorf("improperly formatted script payload sent from database: %q", scriptPayload)
		}

		injector.mu.Lock()

		// Update the local injector
		switch changeType {
		case "UPDATE":
			// Add or update the script URL
			injector.scriptURLs[scriptId] = scriptUrl
		case "DELETE":
			// Delete the script URL
			delete(injector.scriptURLs, scriptId)
		}

		injector.mu.Unlock()
	}
}

// setEnabled sets the injector's "enabled" value to the value provided.
// If an error is returned, the injector's "enabled" value is unchanged.
func (injector *Injector) setEnabled(enabled bool) error {
	injector.mu.Lock()
	defer injector.mu.Unlock()

	// Update local injector
	injector.enabled = enabled

	return nil
}

// isEnabled returns true if the Injector plugin is enabled.
func (injector *Injector) isEnabled() bool {
	// Not using a mutex, because the performance impact is not worth it for this particular data (for now).
	// This method is directly in the critical path for injection checks, and is going to be called a lot.
	// Improving the performance, even a slight bit, is worth a lot over time.
	// injector.mu.RLock()
	// defer injector.mu.RUnlock()

	return injector.enabled
}

// addScriptURL adds the given script URL to the Injector after first checking
// that it is a valid URL and formatting it for uniformity (trimmed
// whitespace).
// If an error is returned, the script URL was not added to the Injector.
func (injector *Injector) addScriptURL(scriptURL string) (scriptID string, err error) {
	// Ensure the given script URL is a properly formatted URL
	if _, parseErr := url.Parse(scriptURL); parseErr != nil {
		return "", fmt.Errorf("invalid URL provided (%q): %w", scriptURL, parseErr)
	}

	// Trim whitespace
	scriptURL = strings.TrimSpace(scriptURL)

	injector.mu.Lock()
	defer injector.mu.Unlock()

	// Start a transaction to update the database
	ctx := context.Background()
	tx, txErr := injector.dbConnPool.Begin(ctx)
	if txErr != nil {
		return "", fmt.Errorf("unable to start database transaction: %w", txErr)
	}

	// Rollback if nothing goes through; safe to perform on an already committed transaction (no-op)
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Add the script URL to the database, returning the new UUID assigned to it
	var id pgtype.UUID
	sqlInsertScriptURL := `insert into injector_script_urls(id, url) VALUES (uuid_generate_v5($1, $2), $2) ON CONFLICT on constraint injector_script_urls_pk DO update SET url = $2 returning id`
	if insertErr := tx.QueryRow(ctx, sqlInsertScriptURL, uuidNameSpace, scriptURL).Scan(&id); insertErr != nil {
		return "", fmt.Errorf("unable to insert script URL into database: %w", insertErr)
	}

	// Convert the new ID value to a string, to save in the local injector
	if uuidConvertErr := id.AssignTo(&scriptID); uuidConvertErr != nil {
		return "", fmt.Errorf("unable to convert UUID value to string: %w", uuidConvertErr)
	}

	// Add the script URL to the existing ones
	injector.scriptURLs[scriptID] = scriptURL

	return
}

// removeScriptURL removes the given script URL from the Injector after first checking
// that it is a valid URL and formatting it for uniformity (trimmed
// whitespace).
// If an error is returned, the script URL was not removed from the Injector.
func (injector *Injector) removeScriptURL(id string) error {
	injector.mu.Lock()
	defer injector.mu.Unlock()

	// Ensure that the provided id/index is valid
	_, exists := injector.scriptURLs[id]
	if !exists {
		return fmt.Errorf("invalid script URL ID provided: %s", id)
	}

	// Start a transaction to update the database
	ctx := context.Background()
	tx, txErr := injector.dbConnPool.Begin(ctx)
	if txErr != nil {
		return fmt.Errorf("unable to start database transaction: %w", txErr)
	}

	// Rollback if nothing goes through; safe to perform on an already committed transaction (no-op)
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Convert the ID value to the appropriate type for use in the database
	var idUUID pgtype.UUID
	if uuidIDSetErr := idUUID.Set(id); uuidIDSetErr != nil {
		return fmt.Errorf("unable to convert string ID to UUID value: %w", uuidIDSetErr)
	}

	// Remove the script URL from the script URLs table
	sqlRemoveScriptURL := `delete from injector_script_urls where id = $1;`
	if _, dbDeleteErr := tx.Exec(ctx, sqlRemoveScriptURL, idUUID); dbDeleteErr != nil {
		return fmt.Errorf("unable to delete script URL from database: %w", dbDeleteErr)
	}

	// Remove the script URL from the injector
	delete(injector.scriptURLs, id)

	return nil
}

// getScriptURLs returns all script URLs saved in the Injector, with a UUIDv5 value as the key for each
// script URL.
func (injector *Injector) getScriptURLs() (scriptURLs map[string]string) {
	injector.mu.RLock()
	defer injector.mu.RUnlock()

	return injector.scriptURLs
}

// getScriptURL returns a single script URL from the injector, using the provided UUIDv5 ID value as
// the key. If no script URL exists for the given key, an empty string is returned.
func (injector *Injector) getScriptURL(id string) string {
	injector.mu.RLock()
	defer injector.mu.RUnlock()

	return injector.scriptURLs[id]
}

// setFromDb overwrites the injector with values from the database.
// This should only ever be called from the NewInjector function.
// Any errors should be considered fatal.
func (injector *Injector) setFromDb() error {
	// Ensure no one is trying to read or write to the injector immediately until this method completes
	injector.mu.Lock()
	defer injector.mu.Unlock()

	ctx := context.Background()

	// Fetch the script URLs and IDs from the database
	sqlSelectTargets := `select id, url from injector_script_urls;`
	rows, queryErr := injector.dbConnPool.Query(ctx, sqlSelectTargets)
	if queryErr != nil {
		return fmt.Errorf("unable to get script URLs from database: %w", queryErr)
	}

	// Ensure the rows are closed; it's safe to close rows multiple times.
	defer rows.Close()

	// Iterate through script URLs
	for rows.Next() {
		var scriptID pgtype.UUID
		var scriptUrl string

		if scanErr := rows.Scan(&scriptID, &scriptUrl); scanErr != nil {
			return fmt.Errorf("problem scanning target result from database into local value: %w", scanErr)
		}

		// Convert the UUID value to a string, for use as the key
		var idStr string
		if uuidConvertErr := scriptID.AssignTo(&idStr); uuidConvertErr != nil {
			return fmt.Errorf("unable to convert script URL UUID key to string: %w", uuidConvertErr)
		}

		// Save the script URL and the ID key to the injector
		injector.scriptURLs[idStr] = scriptUrl
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return nil
}

// JsInResponseHead injects all script URLs into the <head> field of the HTTP response.
// If an error is returned, JavaScript was not successfully injected into the response.
func (injector *Injector) JsInResponseHead(response *http.Response, referrerData datatypes.ReferrerData) error {
	// Only inject if Injector plugin is enabled and there are scripts to inject
	if !injector.isEnabled() {
		return nil
	}

	if response.Body == http.NoBody {
		// This shouldn't happen with an HTML response content-type, but just in case...
		return nil
	}

	// Check that the request is a target
	if !injector.cfg.IsTarget(referrerData.Referer.Host, referrerData.Destination.Host) {
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

	// Prepare the HTML code to inject into the page, right from the DOCTYPE declaration
	jsHeadInject := ""
	for _, script := range injector.scriptURLs {
		// Ignored deleted (empty) script URLs
		if script == "" {
			continue
		}
		jsHeadInject += fmt.Sprintf(`<script type="text/javascript" src=%q></script>`, script)
	}

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

	// TODO: Remove only the necessary part of the "Content-Security-Policy" header, if present, to allow the injection of scripts
	// Remove the "Content-Security-Policy" header, if present, to allow the injection of scripts
	response.Header.Del("Content-Security-Policy")

	// Modify headers
	response.ContentLength = int64(len(respBody))
	response.Header.Set("content-length", fmt.Sprintf("%d", len(respBody)))
	// TODO: Check content-type (encoding) higher up in the code, and only inject if it's "text/html; charset=utf-8",
	// 	or change the character set of the injected content (and associated lookup) to match the content-type.
	response.Header.Set("content-type", "text/html; charset=utf-8")
	response.Header.Del("content-encoding") // sending it uncompressed

	return nil
}
