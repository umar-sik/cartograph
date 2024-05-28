package database

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// ValidateDB tests that the given database is valid, and populates it if
// it is not.
// Returns any errors found, indicating an invalid database connection.
func ValidateDB(dbConn *pgx.Conn) error {
	// Check Postgresql version
	if err := checkServerVersion(dbConn); err != nil {
		return fmt.Errorf("problem with Postgresql database server version check: %w", err)
	}

	// Set timezone
	// if err := setTimezoneUTC(dbConn); err != nil {
	// 	return fmt.Errorf("unable to set timezone to UTC: %w", err)
	// }

	// Enable UUID extension
	if err := setUUIDExtension(dbConn); err != nil {
		return fmt.Errorf("unable to activate UUID extension: %w", err)
	}

	// config_analyzer table
	if err := createTableConfigAnalyzer(dbConn); err != nil {
		return fmt.Errorf("unable to create analyzer config table in database: %w", err)
	}

	// data_analyzer table
	if err := createTableDataAnalyzer(dbConn); err != nil {
		return fmt.Errorf("unable to create analyzer data table in database: %w", err)
	}

	// config_blocker table
	if err := createTableConfigBlocker(dbConn); err != nil {
		return fmt.Errorf("unable to create blocker config table in database: %w", err)
	}

	// data_blocker table
	if err := createTableDataBlocker(dbConn); err != nil {
		return fmt.Errorf("unable to create blocker data table in database: %w", err)
	}

	// config_crawler table
	if err := createTableConfigCrawler(dbConn); err != nil {
		return fmt.Errorf("unable to create crawler config table in database: %w", err)
	}

	// data_crawler table
	if err := createTableDataCrawler(dbConn); err != nil {
		return fmt.Errorf("unable to create crawler data table in database: %w", err)
	}

	// config_dns table
	if err := createTableConfigDNS(dbConn); err != nil {
		return fmt.Errorf("unable to create dns config table in database: %w", err)
	}

	// data_dns table
	if err := createTableDataDNS(dbConn); err != nil {
		return fmt.Errorf("unable to create dns data table in database: %w", err)
	}

	// config_injector table
	if err := createTableConfigInjector(dbConn); err != nil {
		return fmt.Errorf("unable to create injector config table in database: %w", err)
	}

	// data_injector table
	if err := createTableDataInjector(dbConn); err != nil {
		return fmt.Errorf("unable to create injector data table in database: %w", err)
	}

	// config_logger table
	if err := createTableConfigLogger(dbConn); err != nil {
		return fmt.Errorf("unable to create logger config table in database: %w", err)
	}

	// data_logger table
	if err := createTableDataLogger(dbConn); err != nil {
		return fmt.Errorf("unable to create logger data table in database: %w", err)
	}

	// config_mapper table
	if err := createTableConfigMapper(dbConn); err != nil {
		return fmt.Errorf("unable to create mapper config table in database: %w", err)
	}

	// data_mapper table
	if err := createTableDataMapper(dbConn); err != nil {
		return fmt.Errorf("unable to create mapper data table in database: %w", err)
	}

	// API Hunter data table
	if err := createTableDataApiHunter(dbConn); err != nil {
		return fmt.Errorf("unable to create API hunter table in database: %w", err)
	}

	// targets table
	if err := createTableTargets(dbConn); err != nil {
		return fmt.Errorf("unable to create targets table in database: %w", err)
	}

	// injector script URLs table
	if err := createTableInjectorScriptURLs(dbConn); err != nil {
		return fmt.Errorf("unable to create injector script URLs table in database: %w", err)
	}

	// Corpus data - http header keys table
	if err := createTableCorpusHttpHeaderKeys(dbConn); err != nil {
		return fmt.Errorf("unable to create corpus http header keys table in database: %w", err)
	}

	// Corpus data - server header values table
	if err := createTableCorpusServerHeaderValues(dbConn); err != nil {
		return fmt.Errorf("unable to create corpus server header values table in database: %w", err)
	}

	// Corpus data - URL parameter keys table
	if err := createTableCorpusUrlParamKeys(dbConn); err != nil {
		return fmt.Errorf("unable to create corpus URL parameter keys table in database: %w", err)
	}

	// Corpus data - URL path parts table
	if err := createTableCorpusUrlPathParts(dbConn); err != nil {
		return fmt.Errorf("unable to create corpus URL path parts table in database: %w", err)
	}

	// Corpus data - file extensions table
	if err := createTableCorpusFileExtensions(dbConn); err != nil {
		return fmt.Errorf("unable to create corpus file extensions table in database: %w", err)
	}

	// Corpus data - cookie keys table
	if err := createTableCorpusCookieKeys(dbConn); err != nil {
		return fmt.Errorf("unable to create corpus cookie keys table in database: %w", err)
	}

	// Users table
	if err := createTableUsers(dbConn); err != nil {
		return fmt.Errorf("unable to create users table in database: %w", err)
	}

	// User roles table
	if err := createTableUserRoles(dbConn); err != nil {
		return fmt.Errorf("unable to create user roles table in database: %w", err)
	}

	// Vectors table
	if err := createTableVectors(dbConn); err != nil {
		return fmt.Errorf("unable to create vectors table in database: %w", err)
	}

	// Classifications table
	if err := createTableClassifications(dbConn); err != nil {
		return fmt.Errorf("unable to create classifications table in database: %w", err)
	}

	// Stored procedures
	if err := createFunctions(dbConn); err != nil {
		return fmt.Errorf("unable to create functions in database: %w", err)
	}

	// Triggers
	if err := createTriggers(dbConn); err != nil {
		return fmt.Errorf("unable to create triggers in database: %w", err)
	}

	// Operators
	if err := createOperators(dbConn); err != nil {
		return fmt.Errorf("unable to create custom operators in database: %w", err)
	}

	return nil
}

// checkServerVersion checks that the Postgresql database server is on a supported version.
// Any errors returned should be considered fatal.
func checkServerVersion(dbConn *pgx.Conn) error {
	minServerVersionShort := "14.4"
	minServerVersionNum := 140004
	var (
		serverVersionFull  string
		serverVersionShort string
		serverVersionNum   string
	)

	sqlCheckServerVersion := `select version() as version_full, current_setting('server_version') as version_short, current_setting('server_version_num') as version_num;`
	if dbErr := dbConn.QueryRow(context.Background(), sqlCheckServerVersion).Scan(&serverVersionFull, &serverVersionShort, &serverVersionNum); dbErr != nil {
		return fmt.Errorf("unable to check Postgresql database server version number: %w", dbErr)
	}

	// Cast the server version number to an integer
	serverVersionNumInt, intConvErr := strconv.Atoi(serverVersionNum)
	if intConvErr != nil {
		return fmt.Errorf("unable to convert server version number from text to integer type: %w", intConvErr)
	}

	if serverVersionNumInt < minServerVersionNum {
		return fmt.Errorf("unsupported Postgresql database server version %q; minimum supported version is %q", serverVersionShort, minServerVersionShort)
	}

	return nil
}

// setTimezoneUTC sets the database timezone to UTC.
// Any errors returned should be considered fatal.
func setTimezoneUTC(dbConn *pgx.Conn) error {
	sqlSetTimezoneUTC := `SET TIMEZONE = 'UTC';`
	if _, err := dbConn.Exec(context.Background(), sqlSetTimezoneUTC); err != nil {
		return err
	}

	return nil
}

// setUUIDExtension activates the "uuid-ossp" extension, if not already active.
// Any errors returned should be considered fatal.
func setUUIDExtension(dbConn *pgx.Conn) error {
	sqlEnableUUIDExtension := `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`
	if _, err := dbConn.Exec(context.Background(), sqlEnableUUIDExtension); err != nil {
		return err
	}

	return nil
}

// createTableConfigAnalyzer first checks for the existence of the config_analyzer table,
// then creates the table if it does not exist.
// Any errors returned should be considered fatal.
func createTableConfigAnalyzer(dbConn *pgx.Conn) error {
	tableName := "config_analyzer"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `CREATE TABLE IF NOT EXISTS config_analyzer ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from config_analyzer LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataAnalyzer first checks whether the data_analyzer table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataAnalyzer(dbConn *pgx.Conn) error {
	tableName := "data_analyzer"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_analyzer	();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from data_analyzer LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableConfigBlocker first checks for the existence of the config_blocker table,
// then creates the table if it does not exist.
// Any errors returned should be considered fatal.
func createTableConfigBlocker(dbConn *pgx.Conn) error {
	tableName := "config_blocker"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `CREATE TABLE IF NOT EXISTS config_blocker ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from config_blocker LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataBlocker first checks whether the data_blocker table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataBlocker(dbConn *pgx.Conn) error {
	tableName := "data_blocker"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_blocker ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from data_blocker LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableConfigCrawler first checks for the existence of the config_crawler table,
// then creates the table if it does not exist.
// Any errors returned should be considered fatal.
func createTableConfigCrawler(dbConn *pgx.Conn) error {
	tableName := "config_crawler"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `CREATE TABLE IF NOT EXISTS config_crawler ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from config_crawler LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataCrawler first checks whether the data_crawler table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataCrawler(dbConn *pgx.Conn) error {
	tableName := "data_crawler"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_crawler ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from data_crawler LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableConfigDNS first checks for the existence of the config_dns table,
// then creates the table if it does not exist.
// Any errors returned should be considered fatal.
func createTableConfigDNS(dbConn *pgx.Conn) error {
	tableName := "config_dns"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `CREATE TABLE IF NOT EXISTS config_dns ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from config_dns LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataDNS first checks whether the data_dns table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataDNS(dbConn *pgx.Conn) error {
	tableName := "data_dns"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_dns ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from data_dns LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableConfigInjector first checks for the existence of the config_injector table,
// then creates the table if it does not exist.
// Any errors returned should be considered fatal.
func createTableConfigInjector(dbConn *pgx.Conn) error {
	tableName := "config_injector"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists config_injector
			(
				enabled     boolean default true not null,
				targets     uuid[]  default ARRAY []::uuid[],
				ignored     uuid[]  default ARRAY []::uuid[],
				script_urls uuid[]  default ARRAY []::uuid[]
			);
			
			comment on column config_injector.targets is 'An array of UUID values referencing the IDs in the "targets" table.';
			
			comment on column config_injector.ignored is 'An array of UUID values referencing the IDs in the "targets" table.';
			
			comment on column config_injector.script_urls is 'An array of UUID values referencing the IDs in the "injector_script_urls" table.';`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		// Insert default values
		sqlTableInsertDefaultValues := `insert into config_injector default values;`
		if _, err := dbConn.Exec(context.Background(), sqlTableInsertDefaultValues); err != nil {
			return fmt.Errorf("unable to insert default table values: %w", err)
		}

		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT enabled, targets, ignored, script_urls from config_injector LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataInjector first checks whether the data_injector table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataInjector(dbConn *pgx.Conn) error {
	tableName := "data_injector"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_injector ();`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT * from data_injector LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableConfigLogger first checks for the existence of the config_logger table,
// then creates the table and populates it with default values if it does
// not exist.
// Any errors returned should be considered fatal.
func createTableConfigLogger(dbConn *pgx.Conn) error {
	tableName := "config_logger"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists config_logger
			(
				enabled boolean default true             not null,
				targets uuid[]  default ARRAY []::uuid[] not null,
				ignored uuid[]  default ARRAY []::uuid[] not null
			);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		// Insert default values
		sqlTableInsert := `INSERT INTO config_logger default values;`
		if _, err := dbConn.Exec(context.Background(), sqlTableInsert); err != nil {
			return err
		}

		return nil
	}

	sqlTableSelect := `SELECT enabled, targets, ignored FROM config_logger LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataLogger first checks whether the data_logger table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataLogger(dbConn *pgx.Conn) error {
	tableName := "data_logger"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_logger
			(
				url_scheme           text    default ''::text     not null,
				url_host             text                         not null,
				url_path             text    default ''::text     not null,
				date_found           timestamp with time zone     not null,
				req_method           text    default ''::text     not null,
				param_keys           text[]  default '{}'::text[] not null,
				header_keys_req      text[]  default '{}'::text[] not null,
				header_keys_resp     text[]  default '{}'::text[] not null,
				cookie_keys          text[]  default '{}'::text[] not null,
				resp_code            integer default 0            not null,
				param_key_vals       text[]  default '{}'::text[] not null,
				header_key_vals_req  text[]  default '{}'::text[] not null,
				header_key_vals_resp text[]  default '{}'::text[] not null,
				cookie_key_vals      text[]  default '{}'::text[] not null,
				last_seen            timestamp with time zone     not null,
				constraint data_logger_pk
					primary key (url_scheme, url_host, url_path, req_method, resp_code)
			);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT url_scheme, url_host, url_path, date_found, req_method, param_keys, header_keys_req, header_keys_resp, cookie_keys, resp_code, param_key_vals, header_key_vals_req, header_key_vals_resp, cookie_key_vals, last_seen FROM data_logger LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableConfigMapper first checks for the existence of the config_mapper table,
// then creates the table and populates it with default values if it does
// not exist.
// Any errors returned should be considered fatal.
func createTableConfigMapper(dbConn *pgx.Conn) error {
	tableName := "config_mapper"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists config_mapper
			(
				enabled boolean default true             not null,
				targets uuid[]  default ARRAY []::uuid[] not null,
				ignored uuid[]  default ARRAY []::uuid[] not null
			);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}

		// Insert default values
		sqlTableInsert := `INSERT INTO config_mapper default values;`
		if _, err := dbConn.Exec(context.Background(), sqlTableInsert); err != nil {
			return err
		}

		return nil
	}

	sqlTableSelect := `SELECT enabled, targets, ignored FROM config_mapper LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataMapper first checks whether the data_mapper table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataMapper(dbConn *pgx.Conn) error {
	tableName := "data_mapper"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_mapper
			(
				referer_scheme     text default ''::text    not null,
				referer_host       text default ''::text    not null,
				referer_path       text default ''::text    not null,
				destination_scheme text                     not null,
				destination_host   text                     not null,
				destination_path   text                     not null,
				first_seen         timestamp with time zone not null,
				last_seen          timestamp with time zone not null,
				constraint data_mapper_pk
					primary key (referer_scheme, referer_host, referer_path, destination_scheme, destination_host, destination_path)
			);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT referer_scheme, referer_host, referer_path, destination_scheme, destination_host, destination_path, first_seen, last_seen FROM data_mapper LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableTargets first checks whether the targets table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableTargets(dbConn *pgx.Conn) error {
	tableName := "targets"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists targets
			(
				id     uuid    not null
					constraint targets_pk
						primary key,
				ignore boolean not null,
				target jsonb   not null
			);
			
			comment on table targets is 'targets stored in target filter format';
			
			comment on column targets.target is 'Stored in target filter format.';
			
			create unique index if not exists targets_id_uindex
				on targets (id);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, ignore, target FROM targets LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableInjectorScriptURLs first checks whether the injector_script_urls table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableInjectorScriptURLs(dbConn *pgx.Conn) error {
	tableName := "injector_script_urls"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists injector_script_urls
			(
				id  uuid not null
					constraint injector_script_urls_pk
						primary key,
				url text not null
			);
			
			create unique index if not exists injector_script_urls_id_uindex
				on injector_script_urls (id);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, url FROM injector_script_urls LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableDataApiHunter first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableDataApiHunter(dbConn *pgx.Conn) error {
	tableName := "data_api_hunter"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists data_api_hunter
			(
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
			);
			
			comment on table data_api_hunter is 'API data observed in HTTP requests and responses.';
			
			create index if not exists data_api_hunter_index
				on data_api_hunter (url_scheme, url_host, url_path, req_method, resp_code);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT url_scheme, url_scheme, url_host, url_path, req_method, req_body_json, req_body_plain, resp_body_json, resp_body_plain, resp_code, timestamp FROM data_api_hunter LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableCorpusHttpHeaderKeys first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableCorpusHttpHeaderKeys(dbConn *pgx.Conn) error {
	tableName := "corpus_http_header_keys"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists corpus_http_header_keys
			(
				name     varchar(50)                                         not null,
				count    integer                  default 1                  not null,
				keep     boolean                  default true               not null,
				flagged  boolean                  default false              not null,
				reviewed boolean                  default false              not null,
				found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
				id       uuid                     default uuid_generate_v4() not null,
				primary key (id),
				unique (name)
			);
			
			create index if not exists idx_corpus_http_header_keys_flagged
				on corpus_http_header_keys (flagged);
			
			create index if not exists idx_corpus_http_header_keys_reviewed
				on corpus_http_header_keys (reviewed);

			create index if not exists idx_corpus_http_header_keys_found
				on corpus_http_header_keys (found);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, count, keep, flagged, reviewed, found FROM corpus_http_header_keys LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableCorpusCookieKeys first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableCorpusCookieKeys(dbConn *pgx.Conn) error {
	tableName := "corpus_cookie_keys"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists corpus_cookie_keys
			(
				name     varchar(100)                                        not null,
				count    integer                  default 1                  not null,
				keep     boolean                  default true               not null,
				flagged  boolean                  default false              not null,
				reviewed boolean                  default false              not null,
				found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
				id       uuid                     default uuid_generate_v4() not null,
				primary key (id),
				unique (name)
			);
			
			create index if not exists idx_corpus_cookie_keys_flagged
				on corpus_cookie_keys (flagged);
			
			create index if not exists idx_corpus_cookie_keys_reviewed
				on corpus_cookie_keys (reviewed);
			
			create index if not exists idx_corpus_cookie_keys_found
				on corpus_cookie_keys (found);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, count, keep, flagged, reviewed, found FROM corpus_http_header_keys LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableCorpusServerHeaderValues first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableCorpusServerHeaderValues(dbConn *pgx.Conn) error {
	tableName := "corpus_server_header_values"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists corpus_server_header_values
			(
				name     varchar(100)                                        not null,
				count    integer                  default 1                  not null,
				keep     boolean                  default true               not null,
				flagged  boolean                  default false              not null,
				reviewed boolean                  default false              not null,
				found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
				id       uuid                     default uuid_generate_v4() not null,
				primary key (id),
				unique (name)
			);
			
			create index if not exists idx_corpus_server_header_values_flagged
				on corpus_server_header_values (flagged);
			
			create index if not exists idx_corpus_server_header_values_reviewed
				on corpus_server_header_values (reviewed);

			create index if not exists idx_corpus_server_header_values_found
				on corpus_server_header_values (found);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, count, keep, flagged, reviewed, found FROM corpus_server_header_values LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableCorpusUrlParamKeys first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableCorpusUrlParamKeys(dbConn *pgx.Conn) error {
	tableName := "corpus_url_param_keys"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists corpus_url_param_keys
			(
				name     varchar(100)                                        not null,
				count    integer                  default 1                  not null,
				keep     boolean                  default true               not null,
				flagged  boolean                  default false              not null,
				reviewed boolean                  default false              not null,
				found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
				id       uuid                     default uuid_generate_v4() not null,
				primary key (id),
				unique (name)
			);
			
			create index if not exists idx_corpus_url_param_keys_flagged
				on corpus_url_param_keys (flagged);
			
			create index if not exists idx_corpus_url_param_keys_reviewed
				on corpus_url_param_keys (reviewed);
			
			create index if not exists idx_corpus_url_param_keys_found
				on corpus_url_param_keys (found);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, count, keep, flagged, reviewed, found FROM corpus_url_param_keys LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableCorpusUrlPathParts first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableCorpusUrlPathParts(dbConn *pgx.Conn) error {
	tableName := "corpus_url_path_parts"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists corpus_url_path_parts
			(
				name     varchar(50)                                         not null,
				count    integer                  default 1                  not null,
				keep     boolean                  default true               not null,
				flagged  boolean                  default false              not null,
				reviewed boolean                  default false              not null,
				found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
				id       uuid                     default uuid_generate_v4() not null,
				primary key (id),
				unique (name)
			);
			
			create index if not exists idx_corpus_url_path_parts_flagged
				on corpus_url_path_parts (flagged);
			
			create index if not exists idx_corpus_url_path_parts_reviewed
				on corpus_url_path_parts (reviewed);
			
			create index if not exists idx_corpus_url_path_parts_found
				on corpus_url_path_parts (found);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, count, keep, flagged, reviewed, found FROM corpus_url_path_parts LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableCorpusFileExtensions first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableCorpusFileExtensions(dbConn *pgx.Conn) error {
	tableName := "corpus_file_extensions"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists corpus_file_extensions
			(
				name     varchar(50)                                         not null,
				count    integer                  default 1                  not null,
				keep     boolean                  default true               not null,
				flagged  boolean                  default false              not null,
				reviewed boolean                  default false              not null,
				found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
				id       uuid                     default uuid_generate_v4() not null,
				primary key (id),
				unique (name)
			);
			
			create index if not exists idx_corpus_file_extensions_flagged
				on corpus_file_extensions (flagged);
			
			create index if not exists idx_corpus_file_extensions_reviewed
				on corpus_file_extensions (reviewed);
			
			create index if not exists idx_corpus_file_extensions_found
				on corpus_file_extensions (found);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, count, keep, flagged, reviewed, found FROM corpus_file_extensions LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableUsers first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableUsers(dbConn *pgx.Conn) error {
	tableName := "users"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists users
			(
				username   text                                   not null
					constraint users_pk
						primary key,
				password   text                                   not null,
				email      text,
				created_at timestamp with time zone default now() not null,
				roles      integer[]
			);
			
			comment on column users.password is 'Password is stored as an Argon2id hash.';
			
			comment on column users.roles is 'User roles, using the IDs from the user_roles table.';`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT username, email, password, created_at, roles FROM users LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableUserRoles first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableUserRoles(dbConn *pgx.Conn) error {
	tableName := "user_roles"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table user_roles
			(
				id          integer not null
					constraint user_roles_pk
						primary key,
				name        text    not null,
				description text    not null
			);
			
			comment on table user_roles is 'User role descriptions';
			
			comment on column user_roles.id is 'Role ID';
			
			comment on column user_roles.name is 'Name of role';
			
			comment on column user_roles.description is 'Description of role';`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
		return nil
	}

	// Validate the schema
	sqlTableSelect := `SELECT id, name, description FROM user_roles LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	// Insert default data
	sqlInsert := `insert into user_roles (id, name, description) values (0, 'admin', 'Administrator') on conflict do nothing;
		insert into user_roles (id, name, description) values (1, 'review_bow', 'Review and remove bag-of-words values') on conflict do nothing;
		insert into user_roles (id, name, description) values (2, 'review_interesting', 'Review and flag interesting data') on conflict do nothing;
		insert into user_roles (id, name, description) values (3, 'search_similar', 'Search for similar application vectors') on conflict do nothing;`
	if _, err := dbConn.Exec(context.Background(), sqlInsert); err != nil {
		return fmt.Errorf("failed to insert default data into %s table: %w", tableName, err)
	}

	return nil
}

// createTableVectors first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableVectors(dbConn *pgx.Conn) error {
	tableName := "vectors"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists vectors
			(
				url_scheme     text   not null,
				url_host       text   not null,
				url_path       text   not null,
				vector         real[] not null,
				vector_version int    not null,
				constraint vectors_pk
					primary key (url_scheme, url_host, url_path)
			);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
	}

	// Validate the schema
	sqlTableSelect := `SELECT url_scheme, url_host, url_path, vector, vector_version FROM vectors LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createTableClassifications first checks whether the table exists, and
// creates the table if it does not.
// Any errors returned should be considered fatal.
func createTableClassifications(dbConn *pgx.Conn) error {
	tableName := "classifications"

	// Check if table exists
	exists, existsErr := tableExists(dbConn, tableName)
	if existsErr != nil {
		return existsErr
	}
	if !exists {
		// Create table
		sqlTableCreate := `create table if not exists classifications
			(
				url_scheme text   not null,
				url_host   text   not null,
				url_path   text   not null,
				class      int	  not null,
				constraint classifications_pk
					primary key (url_scheme, url_host, url_path)
			);`
		if _, err := dbConn.Exec(context.Background(), sqlTableCreate); err != nil {
			return err
		}
	}

	// Validate the schema
	sqlTableSelect := `SELECT url_scheme, url_host, url_path, class FROM classifications LIMIT 1;`
	rows, queryErr := dbConn.Query(context.Background(), sqlTableSelect)
	if queryErr != nil {
		return fmt.Errorf("%s table is misconfigured; please backup your data from the database and remove the table: %w", tableName, queryErr)
	}
	// Rows must be called and closed for the connection to be used again.
	rows.Close()

	return nil
}

// createFunctions creates the stored procedures needed.
// Any errors returned should be considered fatal.
func createFunctions(dbConn *pgx.Conn) error {
	// Function that gets a list of all hosts and their associated subdomains
	sqlCreateFunctionSubdomains := `CREATE OR REPLACE FUNCTION get_subdomains()
		RETURNS TABLE
				(
					domain    TEXT,
					subdomain TEXT
				)
		LANGUAGE plpgsql
		AS
		$$
		DECLARE
			recdomains     RECORD;
			recsubdomains  RECORD;
			regexsubdomain TEXT;
		BEGIN
			-- Get all unique second-level domains (i.e. example.com or localhost)
			FOR recdomains IN (SELECT DISTINCT unnest(regexp_matches(url_host,
																	 '([a-zA-Z0-9\-_]+|[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)$')) AS domain
							   FROM data_logger)
				LOOP
					-- Search for all subdomains for each second-level domain
					regexsubdomain := '(^([a-zA-Z0-9\-_\.]+\.' || recdomains.domain || ')$)';
					FOR recsubdomains IN (SELECT DISTINCT unnest(regexp_matches(url_host, regexsubdomain)) AS subdomain
										  FROM data_logger)
						LOOP
							-- Assign the domain and subdomain to the table we're returning
							domain := recdomains.domain;
							subdomain := recsubdomains.subdomain;
							RETURN NEXT;
						END LOOP;
					RETURN NEXT;
					IF (SELECT COUNT(*)
						FROM (SELECT DISTINCT unnest(regexp_matches(url_host, regexsubdomain)) AS subdomain
							  FROM data_logger) AS matched) = 0 THEN
						domain := recdomains.domain;
						subdomain := '';
						RETURN NEXT;
					END IF;
				END LOOP;
		END;
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionSubdomains); err != nil {
		return err
	}

	// Function that allows regexp functions to match arrays (case-insensitive)
	sqlCreateFunctionRegexpArrayMatchCaseInsensitive := `CREATE OR REPLACE FUNCTION regexp_match_array_case_insensitive(a TEXT[], regexp TEXT) RETURNS BOOLEAN
		IMMUTABLE
		STRICT
		LANGUAGE SQL
		AS
		$$
		SELECT exists(SELECT * FROM unnest(a) AS x WHERE x ~* regexp);
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionRegexpArrayMatchCaseInsensitive); err != nil {
		return err
	}

	// Function that allows regexp functions to match arrays (case-sensitive)
	sqlCreateFunctionRegexpArrayMatchCaseSensitive := `CREATE OR REPLACE FUNCTION regexp_match_array_case_sensitive(a TEXT[], regexp TEXT) RETURNS BOOLEAN
		IMMUTABLE
		STRICT
		LANGUAGE SQL
		AS
		$$
		SELECT exists(SELECT * FROM unnest(a) AS x WHERE x ~ regexp);
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionRegexpArrayMatchCaseSensitive); err != nil {
		return err
	}

	// Function that allows regexp functions to match arrays (case-insensitive; NOT match)
	sqlCreateFunctionRegexpArrayNotMatchCaseInsensitive := `create or replace function regexp_not_match_array_case_insensitive(a text[], regexp text) returns boolean
			immutable
			strict
			language sql
		as
		$$
		SELECT (exists(SELECT * FROM unnest(a) AS x WHERE x ~* regexp) is false);
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionRegexpArrayNotMatchCaseInsensitive); err != nil {
		return err
	}

	// Function that allows regexp functions to match arrays (case-sensitive; NOT match)
	sqlCreateFunctionRegexpArrayNotMatchCaseSensitive := `create or replace function regexp_not_match_array_case_sensitive(a text[], regexp text) returns boolean
			immutable
			strict
			language sql
		as
		$$
		SELECT (exists(SELECT * FROM unnest(a) AS x WHERE x ~ regexp) is false);
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionRegexpArrayNotMatchCaseSensitive); err != nil {
		return err
	}

	// Function that checks if results exist for an inventory query
	sqlCreateFunctionAPIInventoryAny := `create or replace function inventory_data_exists(start_time timestamp with time zone, domains_regex text[],
														 paths_regex text[], resp_codes integer[], url_schemes_regex text[],
														 req_methods_regex text[], param_keys_regex text[],
														 param_key_values_regex text[], header_keys_req_regex text[],
														 header_key_values_req_regex text[], header_keys_resp_regex text[],
														 header_key_values_resp_regex text[], cookie_keys_regex text[],
														 cookie_key_values_regex text[]) returns boolean
			language plpgsql
		as
		$$
		DECLARE
			rec_domain RECORD;
		BEGIN
			-- Loop through all the given domains
			FOR rec_domain IN (SELECT DISTINCT url_host AS local_domain
							   FROM data_logger
							   WHERE url_host ~* ANY (domains_regex)
							   ORDER BY local_domain)
				LOOP
					-- Return true if there is any data matching the filters provided
					IF EXISTS(SELECT url_path AS local_path
							  FROM data_logger
							  WHERE url_host = rec_domain.local_domain
								AND url_path ~ ANY (paths_regex)
								AND date_found > start_time
								AND resp_code = ANY (resp_codes)
								AND url_scheme ~* ANY (url_schemes_regex)
								AND req_method ~ ANY (req_methods_regex)
								AND param_keys ~@ ANY (param_keys_regex)
								AND param_key_vals ~@ ANY (param_key_values_regex)
								AND header_keys_req ~*@ ANY (header_keys_req_regex)
								AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
								AND header_keys_resp ~*@ ANY (header_keys_resp_regex)
								AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
								AND cookie_keys ~*@ ANY (cookie_keys_regex)
								AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)
						) THEN
						RETURN TRUE;
					END IF;
				END LOOP;
			RETURN FALSE;
		END;
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionAPIInventoryAny); err != nil {
		return err
	}

	// Function that returns results between a given start and end time
	sqlCreateFunctionAPIInventoryAll := `create or replace function get_inventory_data(start_time timestamp with time zone, end_time timestamp with time zone,
													  domains_regex text[],
													  paths_regex text[], resp_codes_int integer[], url_schemes_regex text[],
													  req_methods_regex text[],
													  param_key_values_regex text[],
													  header_key_values_req_regex text[],
													  header_key_values_resp_regex text[],
													  cookie_key_values_regex text[])
			returns TABLE
					(
						host                    text,
						path_val                text,
						param_key_values        text[],
						headers_key_values_req  text[],
						headers_key_values_resp text[],
						cookies_key_values      text[],
						schemes                 text[],
						req_methods             text[],
						resp_codes              integer[],
						last_seen               timestamp with time zone
					)
			language plpgsql
		as
		$$
		DECLARE
			rec_domain RECORD;
			rec_path   RECORD;
		BEGIN
			-- Loop through all the given domains
			FOR rec_domain IN (SELECT DISTINCT url_host AS local_domain
							   FROM data_logger
							   WHERE url_host ~* ANY (domains_regex)
								 AND date_found >= start_time
								 AND last_seen <= end_time
							   ORDER BY local_domain)
				LOOP
					-- Loop through all unique paths for the domain
					FOR rec_path IN (SELECT DISTINCT url_path AS local_path
									 FROM data_logger
									 WHERE url_host = rec_domain.local_domain
									   AND url_path ~ ANY (paths_regex)
									   AND resp_code = ANY (resp_codes_int)
									   AND url_scheme ~* ANY (url_schemes_regex)
									   AND req_method ~ ANY (req_methods_regex)
									   AND param_key_vals ~@ ANY (param_key_values_regex)
									   AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
									   AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
									   AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)
									   AND date_found >= start_time
									   AND last_seen <= end_time
									 ORDER BY local_path)
						LOOP
							-- Get the unique inventory values for the given path and domain
							host := rec_domain.local_domain;
							path_val := rec_path.local_path;
							param_key_values := coalesce((SELECT array_agg(DISTINCT subq.val)
														  FROM (SELECT unnest(param_key_vals) AS val
																FROM data_logger
																WHERE url_host = rec_domain.local_domain
																  AND url_path = rec_path.local_path
																  AND date_found >= start_time
																  AND last_seen <= end_time
																  AND resp_code = ANY (resp_codes_int)
																  AND url_scheme ~* ANY (url_schemes_regex)
																  AND req_method ~ ANY (req_methods_regex)
																  AND param_key_vals ~@ ANY (param_key_values_regex)
																  AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
																  AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
																  AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
														 '{}');
							headers_key_values_req := coalesce((SELECT array_agg(DISTINCT subq.val)
																FROM (SELECT unnest(header_key_vals_req) AS val
																	  FROM data_logger
																	  WHERE url_host = rec_domain.local_domain
																		AND url_path = rec_path.local_path
																		AND date_found >= start_time
																		AND last_seen <= end_time
																		AND resp_code = ANY (resp_codes_int)
																		AND url_scheme ~* ANY (url_schemes_regex)
																		AND req_method ~ ANY (req_methods_regex)
																		AND param_key_vals ~@ ANY (param_key_values_regex)
																		AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
																		AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
																		AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
															   '{}');
							headers_key_values_resp := coalesce((SELECT array_agg(DISTINCT subq.val)
																 FROM (SELECT unnest(header_key_vals_resp) AS val
																	   FROM data_logger
																	   WHERE url_host = rec_domain.local_domain
																		 AND url_path = rec_path.local_path
																		 AND date_found >= start_time
																		 AND last_seen <= end_time
																		 AND resp_code = ANY (resp_codes_int)
																		 AND url_scheme ~* ANY (url_schemes_regex)
																		 AND req_method ~ ANY (req_methods_regex)
																		 AND param_key_vals ~@ ANY (param_key_values_regex)
																		 AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
																		 AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
																		 AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
																'{}');
							cookies_key_values := coalesce((SELECT array_agg(DISTINCT subq.val)
															FROM (SELECT unnest(cookie_key_vals) AS val
																  FROM data_logger
																  WHERE url_host = rec_domain.local_domain
																	AND url_path = rec_path.local_path
																	AND date_found >= start_time
																	AND last_seen <= end_time
																	AND resp_code = ANY (resp_codes_int)
																	AND url_scheme ~* ANY (url_schemes_regex)
																	AND req_method ~ ANY (req_methods_regex)
																	AND param_key_vals ~@ ANY (param_key_values_regex)
																	AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
																	AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
																	AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
														   '{}');
							schemes := coalesce((SELECT array_agg(DISTINCT subq.val)
												 FROM (SELECT url_scheme AS val
													   FROM data_logger
													   WHERE url_host = rec_domain.local_domain
														 AND url_path = rec_path.local_path
														 AND date_found >= start_time
														 AND last_seen <= end_time
														 AND resp_code = ANY (resp_codes_int)
														 AND url_scheme ~* ANY (url_schemes_regex)
														 AND req_method ~ ANY (req_methods_regex)
														 AND param_key_vals ~@ ANY (param_key_values_regex)
														 AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
														 AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
														 AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq), '{}');
							req_methods := coalesce((SELECT array_agg(DISTINCT subq.val)
													 FROM (SELECT req_method AS val
														   FROM data_logger
														   WHERE url_host = rec_domain.local_domain
															 AND url_path = rec_path.local_path
															 AND date_found >= start_time
															 AND last_seen <= end_time
															 AND resp_code = ANY (resp_codes_int)
															 AND url_scheme ~* ANY (url_schemes_regex)
															 AND req_method ~ ANY (req_methods_regex)
															 AND param_key_vals ~@ ANY (param_key_values_regex)
															 AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
															 AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
															 AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
													'{}');
							resp_codes := coalesce((SELECT array_agg(DISTINCT subq.val)
													FROM (SELECT resp_code AS val
														  FROM data_logger
														  WHERE url_host = rec_domain.local_domain
															AND url_path = rec_path.local_path
															AND date_found >= start_time
															AND last_seen <= end_time
															AND resp_code = ANY (resp_codes_int)
															AND url_scheme ~* ANY (url_schemes_regex)
															AND req_method ~ ANY (req_methods_regex)
															AND param_key_vals ~@ ANY (param_key_values_regex)
															AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
															AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
															AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
												   '{}');
							last_seen := (SELECT subq.val
										  FROM (SELECT date_found AS val
												FROM data_logger
												WHERE url_host = rec_domain.local_domain
												  AND url_path = rec_path.local_path
												  AND date_found >= start_time
												  AND last_seen <= end_time
												  AND resp_code = ANY (resp_codes_int)
												  AND url_scheme ~* ANY (url_schemes_regex)
												  AND req_method ~ ANY (req_methods_regex)
												  AND param_key_vals ~@ ANY (param_key_values_regex)
												  AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
												  AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
												  AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)
												ORDER BY date_found DESC
												LIMIT 1) AS subq);
							RETURN NEXT;
						END LOOP;
				END LOOP;
		END;
		$$;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionAPIInventoryAll); err != nil {
		return err
	}

	// Find host connections up to two degrees of separation from a given host.
	sqlCreateFunctionHostConnectionsTwoDegrees := `CREATE OR REPLACE FUNCTION get_referer_destination_host_pairs_within_two_degrees(p_host TEXT)
			RETURNS TABLE
					(
						referer_host          TEXT,
						destination_host      TEXT,
						degrees_of_separation INT
					)
		AS
		$$
		WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
			-- Base case: 1st degree hosts
			SELECT referer_host, destination_host, 1
			FROM data_mapper
			WHERE referer_host = p_host
			   OR destination_host = p_host
		
			UNION
		
			-- Recursive case: up to 3rd degree hosts
			SELECT dm.referer_host,
				   dm.destination_host,
				   cte.depth + 1
			FROM data_mapper dm
					 JOIN cte ON (
						cte.destination_host = dm.referer_host OR cte.destination_host = dm.destination_host OR
						cte.referer_host = dm.referer_host OR cte.referer_host = dm.destination_host
				)
			WHERE cte.depth < 2)
		SELECT DISTINCT referer_host, destination_host, depth as degrees_of_separation
		FROM cte
		where referer_host != ''
		  and destination_host != ''
		  and referer_host != destination_host;
		$$ LANGUAGE sql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionHostConnectionsTwoDegrees); err != nil {
		return err
	}

	// Find host connections up to three degrees of separation from a given host.
	sqlCreateFunctionHostConnectionsThreeDegrees := `CREATE OR REPLACE FUNCTION get_referer_destination_host_pairs_within_three_degrees(p_host TEXT)
			RETURNS TABLE
					(
						referer_host          TEXT,
						destination_host      TEXT,
						degrees_of_separation INT
					)
		AS
		$$
		WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
			-- Base case: 1st degree hosts
			SELECT referer_host, destination_host, 1
			FROM data_mapper
			WHERE referer_host = p_host
			   OR destination_host = p_host
		
			UNION
		
			-- Recursive case: up to 3rd degree hosts
			SELECT dm.referer_host,
				   dm.destination_host,
				   cte.depth + 1
			FROM data_mapper dm
					 JOIN cte ON (
						cte.destination_host = dm.referer_host OR cte.destination_host = dm.destination_host OR
						cte.referer_host = dm.referer_host OR cte.referer_host = dm.destination_host
				)
			WHERE cte.depth < 3)
		SELECT DISTINCT referer_host, destination_host, depth as degrees_of_separation
		FROM cte
		where referer_host != ''
		  and destination_host != ''
		  and referer_host != destination_host;
		$$ LANGUAGE sql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionHostConnectionsThreeDegrees); err != nil {
		return err
	}

	// Find host connections up to four degrees of separation from a given host.
	sqlCreateFunctionHostConnectionsFourDegrees := `CREATE OR REPLACE FUNCTION get_referer_destination_host_pairs_within_four_degrees(p_host TEXT)
			RETURNS TABLE
					(
						referer_host          TEXT,
						destination_host      TEXT,
						degrees_of_separation INT
					)
		AS
		$$
		WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
			-- Base case: 1st degree hosts
			SELECT referer_host, destination_host, 1
			FROM data_mapper
			WHERE referer_host = p_host
			   OR destination_host = p_host
		
			UNION
		
			-- Recursive case: up to 3rd degree hosts
			SELECT dm.referer_host,
				   dm.destination_host,
				   cte.depth + 1
			FROM data_mapper dm
					 JOIN cte ON (
						cte.destination_host = dm.referer_host OR cte.destination_host = dm.destination_host OR
						cte.referer_host = dm.referer_host OR cte.referer_host = dm.destination_host
				)
			WHERE cte.depth < 4)
		SELECT DISTINCT referer_host, destination_host, depth as degrees_of_separation
		FROM cte
		where referer_host != ''
		  and destination_host != ''
		  and referer_host != destination_host;
		$$ LANGUAGE sql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionHostConnectionsFourDegrees); err != nil {
		return err
	}

	// Get all directly connected hosts for a given array of hosts
	sqlCreateFunctionConnectedHosts := `CREATE OR REPLACE FUNCTION get_paths_and_connected_hosts(p_hosts TEXT[])
			RETURNS TABLE
					(
						source      TEXT,
						destination TEXT
					)
		AS
		$$
		BEGIN
			RETURN QUERY
				SELECT DISTINCT ON (sub.source, sub.destination) sub.source, sub.destination
				FROM (SELECT CASE
								 WHEN referer_host = ANY (p_hosts)
									 THEN referer_host || CASE WHEN referer_path = '/' THEN '' ELSE referer_path END
								 ELSE referer_host
								 END AS source,
							 CASE
								 WHEN destination_host = ANY (p_hosts) THEN destination_host || CASE
																									WHEN destination_path = '/'
																										THEN ''
																									ELSE destination_path END
								 ELSE destination_host
								 END AS destination
					  FROM data_mapper
					  WHERE referer_host = ANY (p_hosts)
						 OR destination_host = ANY (p_hosts)
						  AND referer_host != '') AS sub
				WHERE sub.source != sub.destination
				ORDER BY sub.source, sub.destination;
		END;
		$$ LANGUAGE plpgsql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionConnectedHosts); err != nil {
		return err
	}

	// Get all paths and directly connected hosts for a given array of hosts
	sqlCreateFunctionPathsAndConnectedHosts := `CREATE OR REPLACE FUNCTION get_paths_and_connected_hosts(p_hosts TEXT[])
			RETURNS TABLE
					(
						source      TEXT,
						destination TEXT
					)
		AS
		$$
		BEGIN
			RETURN QUERY
				-- When the given host is the referer_host
				SELECT DISTINCT ON (source, destination) CASE
															 WHEN referer_host = ANY (p_hosts)
																 THEN referer_host || CASE WHEN referer_path = '/' THEN '' ELSE referer_path END
															 ELSE referer_host
															 END AS source,
														 CASE
															 WHEN destination_host = ANY (p_hosts) THEN destination_host || CASE
																																WHEN destination_path = '/'
																																	THEN ''
																																ELSE destination_path END
															 ELSE destination_host
															 END AS destination
				FROM data_mapper
				WHERE referer_host = ANY (p_hosts)
				   OR destination_host = ANY (p_hosts)
					AND referer_host != destination_host
					AND destination != ''
					AND source != ''
				ORDER BY source, destination;
		END;
		$$ LANGUAGE plpgsql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionPathsAndConnectedHosts); err != nil {
		return err
	}

	// Get classifications for hosts and paths that are found in the data_mapper table for a given set of hosts
	sqlCreateFunctionGetClassificationsForMapperData := `CREATE OR REPLACE FUNCTION get_classifications_for_mapper_data(p_url_hosts TEXT[])
			RETURNS TABLE
					(
						url_scheme TEXT,
						url_host   TEXT,
						url_path   TEXT,
						class      INT
					)
		AS
		$$
		BEGIN
			RETURN QUERY
				SELECT c.url_scheme, c.url_host, c.url_path, c.class
				FROM classifications c
				WHERE c.url_host = ANY (p_url_hosts)
				  AND (
						EXISTS (SELECT 1
								FROM data_mapper dm
								WHERE dm.referer_scheme = c.url_scheme
								  AND dm.referer_host = c.url_host
								  AND dm.referer_path = c.url_path) OR EXISTS (SELECT 1
																			   FROM data_mapper dm
																			   WHERE dm.destination_scheme = c.url_scheme
																				 AND dm.destination_host = c.url_host
																				 AND dm.destination_path = c.url_path)
					);
		END;
		$$ LANGUAGE plpgsql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionGetClassificationsForMapperData); err != nil {
		return err
	}

	// Get connected hosts - one degree of separation
	sqlCreateFunctionGetConnectedHosts := `CREATE OR REPLACE FUNCTION get_connected_hosts(p_hosts TEXT[])
				RETURNS TABLE
						(
							ref_host  TEXT,
							dest_host TEXT
						)
			AS
			$$
			BEGIN
				RETURN QUERY
					(
						-- When the given host is the referer_host
						SELECT referer_host     AS ref_host,
							   destination_host AS dest_host
						FROM data_mapper
						WHERE referer_host = ANY (p_hosts)
						  AND destination_host <> ''
						  AND referer_host <> destination_host)
					UNION
					(
						-- When the given host is the destination_host
						SELECT referer_host     AS ref_host,
							   destination_host AS dest_host
						FROM data_mapper
						WHERE destination_host = ANY (p_hosts)
						  AND referer_host <> ''
						  AND referer_host <> destination_host)
					ORDER BY ref_host, dest_host;
			END;
			$$ LANGUAGE plpgsql;`
	if _, err := dbConn.Exec(context.Background(), sqlCreateFunctionGetConnectedHosts); err != nil {
		return err
	}

	return nil
}

// createTriggers creates the database triggers needed.
// Any errors returned should be considered fatal.
func createTriggers(dbConn *pgx.Conn) error {
	// Triggers after every update to config table columns.
	// These are used to notify distributed deployments about a change to the source of truth (the database).
	sqlCreateTriggerInjectorScriptUrls := `CREATE OR REPLACE FUNCTION notify_change_on_injector_script_urls()
			RETURNS TRIGGER AS
		$$
		DECLARE
			operation TEXT;
		BEGIN
			IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
				operation := 'UPDATE';
			ELSIF TG_OP = 'DELETE' THEN
				operation := 'DELETE';
			END IF;
		
			PERFORM pg_notify('injector_script_urls_channel', operation || ',' || NEW.id::text || ':' || NEW.url);
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		
		CREATE OR REPLACE TRIGGER injector_script_urls_trigger
			AFTER INSERT OR UPDATE OR DELETE
			ON injector_script_urls
			FOR EACH ROW
		EXECUTE FUNCTION notify_change_on_injector_script_urls();`
	if _, err := dbConn.Exec(context.Background(), sqlCreateTriggerInjectorScriptUrls); err != nil {
		return err
	}

	sqlCreateTriggerTargets := `CREATE OR REPLACE FUNCTION notify_change_on_targets()
			RETURNS TRIGGER AS
		$$
		DECLARE
			operation TEXT;
		BEGIN
			IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
				operation := 'UPDATE';
			ELSIF TG_OP = 'DELETE' THEN
				operation := 'DELETE';
			END IF;
		
			PERFORM pg_notify('targets_channel', operation || ',' || NEW.id::text || ':' || NEW.target::jsonb::text);
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		
		CREATE OR REPLACE TRIGGER targets_trigger
			AFTER INSERT OR UPDATE OR DELETE
			ON targets
			FOR EACH ROW
		EXECUTE FUNCTION notify_change_on_targets();`
	if _, err := dbConn.Exec(context.Background(), sqlCreateTriggerTargets); err != nil {
		return err
	}

	return nil
}

// createOperators creates the custom operators we need in the database.
// Any errors returned should be considered fatal.
func createOperators(dbConn *pgx.Conn) error {
	// ~*@ : This operator allows us to check whether any two arrays match,
	// ignoring case (think ANY(ARRAY) ~* REGEXP).

	// Try to drop the operator
	sqlDropOperatorCaseInsensitiveArrayMatch := `DROP OPERATOR IF EXISTS ~*@ (TEXT[], text);`
	if _, err := dbConn.Exec(context.Background(), sqlDropOperatorCaseInsensitiveArrayMatch); err != nil {
		return err
	}
	// Create the operator
	sqlCreateOperatorCaseInsensitiveArrayMatch := `CREATE OPERATOR ~*@ (PROCEDURE = regexp_match_array_case_insensitive, LEFTARG = TEXT[], RIGHTARG = TEXT);`
	if _, err := dbConn.Exec(context.Background(), sqlCreateOperatorCaseInsensitiveArrayMatch); err != nil {
		return err
	}

	// ~* : This operator allows us to check whether any two arrays match,
	// matching case (think ANY(ARRAY) ~ REGEXP).

	// Try to drop the operator
	sqlDropOperatorCaseSensitiveArrayMatch := `DROP OPERATOR IF EXISTS ~@ (TEXT[], text);`
	if _, err := dbConn.Exec(context.Background(), sqlDropOperatorCaseSensitiveArrayMatch); err != nil {
		return err
	}
	// Create the operator
	sqlCreateOperatorCaseSensitiveArrayMatch := `CREATE OPERATOR ~@ (PROCEDURE = regexp_match_array_case_sensitive, LEFTARG = TEXT[], RIGHTARG = TEXT);`
	if _, err := dbConn.Exec(context.Background(), sqlCreateOperatorCaseSensitiveArrayMatch); err != nil {
		return err
	}

	// !~*@ : This operator allows us to check whether any two arrays do NOT match,
	// ignoring case (think ANY(ARRAY) !~* REGEXP).

	// Try to drop the operator
	sqlDropOperatorCaseInsensitiveArrayNotMatch := `DROP OPERATOR IF EXISTS !~*@ (TEXT[], text);`
	if _, err := dbConn.Exec(context.Background(), sqlDropOperatorCaseInsensitiveArrayNotMatch); err != nil {
		return err
	}
	// Create the operator
	sqlCreateOperatorCaseInsensitiveArrayNotMatch := `create operator !~*@ (procedure = regexp_not_match_array_case_insensitive, leftarg = text[], rightarg = text);`
	if _, err := dbConn.Exec(context.Background(), sqlCreateOperatorCaseInsensitiveArrayNotMatch); err != nil {
		return err
	}

	// ~* : This operator allows us to check whether any two arrays do NOT match,
	// matching case (think ANY(ARRAY) !~ REGEXP).

	// Try to drop the operator
	sqlDropOperatorCaseSensitiveArrayNotMatch := `DROP OPERATOR IF EXISTS !~@ (TEXT[], text);`
	if _, err := dbConn.Exec(context.Background(), sqlDropOperatorCaseSensitiveArrayNotMatch); err != nil {
		return err
	}
	// Create the operator
	sqlCreateOperatorCaseSensitiveArrayNotMatch := `create operator !~@ (procedure = regexp_not_match_array_case_sensitive, leftarg = text[], rightarg = text);`
	if _, err := dbConn.Exec(context.Background(), sqlCreateOperatorCaseSensitiveArrayNotMatch); err != nil {
		return err
	}

	return nil
}

// tableExists checks whether the given table name exists in the "public"
// database schema.
// Any errors returned should be considered fatal.
func tableExists(dbConn *pgx.Conn, tableName string) (bool, error) {
	var exists bool
	sqlTableCheck := `SELECT EXISTS (
		SELECT 1
		FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		AND c.relname = $1);`
	if err := dbConn.QueryRow(context.Background(), sqlTableCheck, tableName).Scan(&exists); err != nil {
		return false, err
	}

	return exists, nil
}
