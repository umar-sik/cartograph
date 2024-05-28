package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pgxuuid "github.com/jackc/pgx-gofrs-uuid"
)

// GetDbConnPool parses the given config byte array (created from TOML config file) and returns a database
// connection pool.
func GetDbConnPool(dbConnString string) (*pgxpool.Pool, error) {
	// Create a database connection config
	pgxPoolConfig, configErr := pgxpool.ParseConfig(dbConnString)
	if configErr != nil {
		return nil, fmt.Errorf("unable to parse database connection string: %w", configErr)
	}

	// Add support for UUIDs
	pgxPoolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		pgxuuid.Register(conn.TypeMap())
		return nil
	}

	// Create the database connection pool
	dbConnPool, connErr := pgxpool.NewWithConfig(context.Background(), pgxPoolConfig)
	if connErr != nil {
		return nil, fmt.Errorf("unable to create database connection pool from database config: %w", connErr)
	}

	return dbConnPool, nil
}
