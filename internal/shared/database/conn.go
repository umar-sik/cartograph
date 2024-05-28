package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GetDbConn parses the given config byte array (created from TOML config file) and returns a database connection.
func GetDbConn(dbConnString string) (*pgx.Conn, error) {
	// Create a database connection config
	pgxConfig, configErr := pgx.ParseConfig(dbConnString)
	if configErr != nil {
		return nil, fmt.Errorf("unable to parse database connection string: %w", configErr)
	}

	// Create the database connection pool
	dbConn, connErr := pgx.ConnectConfig(context.Background(), pgxConfig)
	if connErr != nil {
		return nil, fmt.Errorf("unable to create database connection from database config: %w", connErr)
	}

	return dbConn, nil
}
