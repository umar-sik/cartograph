package config

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/shared/database"
	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
)

// NewConfig initializes the program and returns a new instance of the Config object.
// Any errors returned should be considered fatal.
func NewConfig() (*Config, error) {
	config := &Config{
		targets:       make(map[string]*datatypes.TargetIgnoreSimple),
		ignored:       make(map[string]*datatypes.TargetIgnoreSimple),
		uuidNamespace: uuid.Must(uuid.FromString("61970c6a-6d09-4502-88fd-5ecff9150956")),
	}

	// Check if training mode is enabled
	trainingMode := flag.Bool("training", false, "enable training mode")

	// Mapper injection scripts directory
	mapperScriptDir := flag.String("mapper-script-dir", "", "the location of the mapper script directory")

	// Parse command-line flags
	flag.Parse()

	// Set database connection string
	var dbConnStringErr error
	if config.DbConnString, dbConnStringErr = getDbFromEnv(); dbConnStringErr != nil {
		return nil, fmt.Errorf("unable to escape database connection string: %w", dbConnStringErr)
	}

	// Set SOCKS5 proxy connection string
	var socks5ProxyStringErr error
	if config.Socks5ProxyString, socks5ProxyStringErr = getSocks5ProxyFromEnv(); socks5ProxyStringErr != nil {
		log.WithError(socks5ProxyStringErr).Debug("unable to get SOCKS5 proxy connection string from environment")
	}

	// Set training mode
	config.TrainingMode = *trainingMode

	// Set mapper script directory
	if *mapperScriptDir == "" {
		return nil, fmt.Errorf("no mapper script directory provided with '--mapper-script-dir' flag")
	}
	config.MapperScriptDir = *mapperScriptDir

	// Get a database connection pool
	conn, connErr := database.GetDbConnPool(config.DbConnString)
	if connErr != nil {
		return nil, fmt.Errorf("unable to get database connection pool: %w", connErr)
	}
	config.dbConnPool = conn

	// Validate the database; retry every 5 seconds, for a maximum of 30 seconds
	for i := 0; i < 6; i++ {
		tmpConn, acquireErr := conn.Acquire(context.Background())
		if acquireErr != nil {
			if i == 5 {
				return nil, fmt.Errorf("unable to acquire database connection: %w", acquireErr)
			}
			log.WithError(acquireErr).Warn("unable to acquire database connection; retrying in 5 seconds")
			time.Sleep(5 * time.Second)
			continue
		}

		validateErr := database.ValidateDB(tmpConn.Conn())
		if validateErr != nil {
			return nil, fmt.Errorf("unable to validate database: %w", validateErr)
		}

		tmpConn.Release()
		break
	}

	// Get all the target rule sets from the database
	ctx := context.Background()
	sqlSelectTargets := `select id, target from targets;`
	rows, queryErr := conn.Query(ctx, sqlSelectTargets)
	if queryErr != nil {
		return nil, fmt.Errorf("unable to get targets from database: %w", queryErr)
	}

	// Ensure the rows are closed; it's safe to close rows multiple times.
	defer rows.Close()

	// Iterate through targets
	for rows.Next() {
		var targetID pgtype.UUID
		var targetFilter datatypes.TargetFilterSimple

		if scanErr := rows.Scan(&targetID, &targetFilter); scanErr != nil {
			return nil, fmt.Errorf("problem scanning target result from database into local value: %w", scanErr)
		}

		// Convert the target filter to a proper target/ignore rule set
		target, tfConvertErr := targetFilter.ToTargetIgnoreSimple()
		if tfConvertErr != nil {
			return nil, fmt.Errorf("unable to convert target filter rule to target/ignore rule set: %w", tfConvertErr)
		}

		// Convert the UUID value to a string, for use as the key
		var idStr string
		if uuidConvertErr := targetID.AssignTo(&idStr); uuidConvertErr != nil {
			return nil, fmt.Errorf("unable to convert target UUID key to string: %w", uuidConvertErr)
		}

		// Save the target/ignore rule set and the ID to the logger
		if target.IsIgnore {
			config.ignored[idStr] = target
		} else {
			config.targets[idStr] = target
		}
	}

	// One final check for errors encountered by rows.Next or rows.Scan
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unexpected error returned from database rows: %w", rowsErr)
	}

	return config, nil
}

// getDbFromEnv creates a database connection string from the values stored in environment variables.
func getDbFromEnv() (string, error) {
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		return "", fmt.Errorf("no database host provided in environment variable 'DB_HOST'")
	}
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		return "", fmt.Errorf("no database name provided in environment variable 'DB_NAME'")
	}

	// Create the database connection string
	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", url.QueryEscape(dbUser), url.QueryEscape(dbPass), url.QueryEscape(dbHost), dbPort, url.QueryEscape(dbName)), nil
}

// getSocks5ProxyFromEnv creates a SOCKS5 proxy string from the values stored in environment variables.
func getSocks5ProxyFromEnv() (string, error) {
	socksUser := os.Getenv("SOCKS5_USER")
	socksPass := os.Getenv("SOCKS5_PASS")
	socksHost := os.Getenv("SOCKS5_HOST")
	if socksHost == "" {
		return "", fmt.Errorf("no SOCKS5 host provided in environment variable 'SOCKS5_HOST'")
	}
	socksPort := os.Getenv("SOCKS5_PORT")
	if socksPort == "" {
		return "", fmt.Errorf("no SOCKS5 port provided in environment variable 'SOCKS5_PORT'")
	}

	// Create the SOCKS5 proxy string
	return fmt.Sprintf("socks5://%s:%s@%s:%s", url.QueryEscape(socksUser), url.QueryEscape(socksPass), url.QueryEscape(socksHost), socksPort), nil
}

// Config holds all the configuration data for the application.
type Config struct {
	mu sync.RWMutex

	// DbConnString is the connection string for the database.
	DbConnString string

	// Socks5ProxyString is the connection string for the SOCKS5 proxy.
	// It is empty if no proxy is used.
	Socks5ProxyString string

	// TrainingMode is true if training mode is enabled.
	TrainingMode bool

	// MapperScriptDir is the directory where mapper injection scripts are stored.
	MapperScriptDir string

	// uuidNamespace is the UUID namespace used for generating UUIDv5 keys.
	uuidNamespace uuid.UUID

	// targets holds all target rule sets, mapped to a UUIDv5 key.
	targets map[string]*datatypes.TargetIgnoreSimple

	// ignored holds all the ignored target rule sets, mapped to a UUIDv5 key.
	ignored map[string]*datatypes.TargetIgnoreSimple

	// dbConnPool is the database connection pool.
	dbConnPool *pgxpool.Pool

	// listenDbConn is the database connection used for listening for NOTIFY events.
	listenDbConn *pgx.Conn
}

// dbMonitor listens for updates to the targets table in the database.
// When a change is detected, it updates the target and ignored maps in the Config.
func (c *Config) dbMonitor(ctx context.Context) error {
	// Establish the listener
	listenChannel := "targets_channel"
	_, listenErr := c.listenDbConn.Exec(ctx, fmt.Sprintf("LISTEN %s", listenChannel))
	if listenErr != nil {
		return fmt.Errorf("unable to listen for database changes: %w", listenErr)
	}

	// Wait for notification
	for {
		// Wait for a notification
		notify, notifyErr := c.listenDbConn.WaitForNotification(ctx)
		if notifyErr != nil {
			return fmt.Errorf("error waiting for database notification: %w", notifyErr)
		}

		// Determine the type of update
		changeType, updatePayload, separatorFound := strings.Cut(notify.Payload, ",")
		if !separatorFound {
			return fmt.Errorf("unable to parse database notification payload: %s", notify.Payload)
		}

		// Get the ID of the target that was updated, and the update target content
		targetId, targetContent, targetSeparatorFound := strings.Cut(updatePayload, ":")
		if !targetSeparatorFound {
			return fmt.Errorf("unable to parse database notification target payload: %s", notify.Payload)
		}

		c.mu.Lock()

		// Update the target or ignored map
		switch changeType {
		case "UPDATE":
			// Convert the targetContent to JSON
			var target datatypes.TargetFilterSimple
			if jsonErr := json.Unmarshal([]byte(targetContent), &target); jsonErr != nil {
				return fmt.Errorf("unable to parse database notification target content to JSON: %w", jsonErr)
			}

			// Convert the target to a TargetIgnoreSimple
			targetIgnore, convertErr := target.ToTargetIgnoreSimple()
			if convertErr != nil {
				return fmt.Errorf("unable to convert target to TargetIgnoreSimple: %w", convertErr)
			}

			// Update the target or ignored map
			if target.Ignore {
				c.ignored[targetId] = targetIgnore
			} else {
				c.targets[targetId] = targetIgnore
			}
		case "DELETE":
			// Delete the target or ignored map
			if _, ok := c.ignored[targetId]; ok {
				delete(c.ignored, targetId)
			} else if _, ok := c.targets[targetId]; ok {
				delete(c.targets, targetId)
			} else {
				return fmt.Errorf("unable to find target with ID '%s' in targets or ignored maps", targetId)
			}
		}
	}
}

// getTargetsAll returns all the target rule sets.
func (c *Config) getTargetsAll() map[string]*datatypes.TargetIgnoreSimple {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.targets
}

// getIgnoredAll returns all the ignored target rule sets.
func (c *Config) getIgnoredAll() map[string]*datatypes.TargetIgnoreSimple {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.ignored
}

// GetTargetsAndIgnoredAll returns all the target and ignored rule sets.
func (c *Config) GetTargetsAndIgnoredAll() map[string]*datatypes.TargetIgnoreSimple {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create the map
	targetsAndIgnored := make(map[string]*datatypes.TargetIgnoreSimple)

	// Add the targets
	for id, target := range c.targets {
		targetsAndIgnored[id] = target
	}

	// Add the ignored
	for id, ignored := range c.ignored {
		targetsAndIgnored[id] = ignored
	}

	return targetsAndIgnored
}

// getTargetSingle returns the target rule set with the given ID.
func (c *Config) getTargetSingle(id string) (*datatypes.TargetIgnoreSimple, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	target, ok := c.targets[id]
	if !ok {
		return nil, fmt.Errorf("no target found with ID '%s'", id)
	}

	return target, nil
}

// getIgnoredSingle returns the ignored target rule set with the given ID.
func (c *Config) getIgnoredSingle(id string) (*datatypes.TargetIgnoreSimple, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ignored, ok := c.ignored[id]
	if !ok {
		return nil, fmt.Errorf("no ignored target found with ID '%s'", id)
	}

	return ignored, nil
}

// addTargetOrIgnored adds a new target rule set to the configuration.
// It returns the ID of the new rule.
// If the target already exists, it returns the ID of the existing target.
// If the target is invalid, it returns an error.
func (c *Config) addTargetOrIgnored(target *datatypes.TargetFilterSimple) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Convert the target filter to JSON for inserting into the database, and for generating a UUID
	targetFilterJSON, jsonErr := json.Marshal(target)
	if jsonErr != nil {
		return "", fmt.Errorf("unable to convert target filter to JSON: %w", jsonErr)
	}

	// Generate a UUIDv5 for the target, based on the JSON representation of the target filter
	targetID := uuid.NewV5(c.uuidNamespace, string(targetFilterJSON))

	// Check if the target already exists
	if target.Ignore {
		if _, ok := c.ignored[targetID.String()]; ok {
			return targetID.String(), nil
		}
	} else {
		if _, ok := c.targets[targetID.String()]; ok {
			return targetID.String(), nil
		}
	}

	// Insert the target into the database
	_, insertErr := c.dbConnPool.Exec(context.Background(), "INSERT INTO targets (id, ignore, target) VALUES ($1, $2, $3::jsonb) on conflict ON CONSTRAINT targets_pk DO update set ignore = $2;", targetID, target.Ignore, targetFilterJSON)
	if insertErr != nil {
		return "", fmt.Errorf("unable to insert target into database: %w", insertErr)
	}

	// Convert the target filter to a proper target/ignore rule set
	targetRule, tfConvertErr := target.ToTargetIgnoreSimple()
	if tfConvertErr != nil {
		return "", fmt.Errorf("unable to convert target filter rule to target/ignore rule set: %w", tfConvertErr)
	}

	// Add the target to the configuration
	if target.Ignore {
		c.ignored[targetID.String()] = targetRule
	} else {
		c.targets[targetID.String()] = targetRule
	}

	return targetID.String(), nil
}

// deleteTargetOrIgnored deletes the target rule set with the given ID.
func (c *Config) deleteTargetOrIgnored(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Delete the target from the database
	_, deleteErr := c.dbConnPool.Exec(context.Background(), "DELETE FROM targets WHERE id = $1;", id)
	if deleteErr != nil {
		return fmt.Errorf("unable to delete target from database: %w", deleteErr)
	}

	// Delete the target from the configuration
	delete(c.targets, id)
	delete(c.ignored, id)

	return nil
}

// IsTarget returns true if the given source or destination hosts are a target.
// It returns false if the hosts are not a target, or if the hosts are ignored.
func (c *Config) IsTarget(srcHost, dstHost string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if the hosts are ignored
	for _, ignored := range c.ignored {
		if ignored.MatchesHost(srcHost, dstHost) {
			return false
		}
	}

	// Check if the hosts are targets
	for _, target := range c.targets {
		if target.MatchesHost(srcHost, dstHost) {
			return true
		}
	}

	return false
}
