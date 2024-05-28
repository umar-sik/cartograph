package mapper

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lib/pq"
	"golang.org/x/sync/errgroup"

	"github.com/TheHackerDev/cartograph/internal/shared/datatypes/gexf"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

// SourceURL is a struct that holds the scheme, host, and path of a URL for use in the mapper data API.
type SourceURL struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

// ConnectionsOutput holds the data for connections to and from a single URL.
type ConnectionsOutput struct {
	SourceURL       SourceURL         `json:"source_url"`
	ConnectionsTo   ConnectionsToFrom `json:"connections_to"`
	ConnectionsFrom ConnectionsToFrom `json:"connections_from"`
}

// ConnectionsToFrom holds the data for connections either to or from a single source URL.
type ConnectionsToFrom struct {
	Count       int          `json:"count"`
	Connections []Connection `json:"connections"`
}

// Connection represents a single connecting URL to or from a source URL.
type Connection struct {
	URL       string    `json:"url"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// HostsDataAPIHandler handles requests to the mapper data API for all connecting hosts to and from a given URL.
// Only POST requests are allowed, as we need the source URL data in the request body.
func (m *Mapper) HostsDataAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests (or OPTIONS)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "POST, OPTIONS")
		return
	} else if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "POST, OPTIONS")
		return
	}

	// Attempt to parse the source URL from the request
	reqBody, bodyCopy, bodyReadErr := internalHttp.ReadBody(r.Body)
	r.Body = bodyCopy
	if bodyReadErr != nil {
		http.Error(w, fmt.Sprintf("unable to read request body: %s", bodyReadErr.Error()), http.StatusInternalServerError)
		return
	}
	var sourceURL SourceURL
	if jsonUnMarshalErr := json.Unmarshal(reqBody, &sourceURL); jsonUnMarshalErr != nil {
		http.Error(w, fmt.Sprintf("unable to parse JSON request body into source URL object: %s", jsonUnMarshalErr.Error()), http.StatusInternalServerError)
		return
	}

	// Get the host connections data
	data, getErr := m.getConnectingHosts(&sourceURL)
	if getErr != nil {
		http.Error(w, fmt.Sprintf("unable to get data for given source URL: %s", getErr.Error()), http.StatusInternalServerError)
		return
	}

	// Convert http data to JSON to return to client
	dataJson, dJsonMarshalErr := json.Marshal(data)
	if dJsonMarshalErr != nil {
		http.Error(w, fmt.Sprintf("unable to convert data to JSON: %s", dJsonMarshalErr.Error()), http.StatusInternalServerError)
		return
	}

	// Set the appropriate header for the content type in the response
	w.Header().Set("Content-Type", "application/json")

	// Write the response
	if _, writeErr := w.Write(dataJson); writeErr != nil {
		http.Error(w, fmt.Sprintf("problem writing JSON response back: %s", writeErr.Error()), http.StatusInternalServerError)
		return
	}
}

// getConnectingHosts gets the data for connections to and from a given source URL.
// The source URL must include a host, but can optionally include a scheme and path.
func (m *Mapper) getConnectingHosts(sourceURL *SourceURL) (*ConnectionsOutput, error) {
	eg := new(errgroup.Group)

	// Get the connections to the source URL
	connectionsTo := new(ConnectionsToFrom)
	eg.Go(func() error {
		var getToErr error
		connectionsTo, getToErr = m.getHostConnectionsTo(sourceURL)
		if getToErr != nil {
			return fmt.Errorf("unable to get connections to source URL: %w", getToErr)
		}

		return nil
	})

	// Get the connections from the source URL
	connectionsFrom := new(ConnectionsToFrom)
	eg.Go(func() error {
		var getFromErr error
		connectionsFrom, getFromErr = m.getHostConnectionsFrom(sourceURL)
		if getFromErr != nil {
			return fmt.Errorf("unable to get connections from source URL: %w", getFromErr)
		}

		return nil
	})

	// Wait for the goroutines to finish
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("unable to get connecting hosts data: %w", err)
	}

	// Return the data
	return &ConnectionsOutput{
		SourceURL:       *sourceURL,
		ConnectionsTo:   *connectionsTo,
		ConnectionsFrom: *connectionsFrom,
	}, nil
}

// getHostConnectionsTo gets the host data for connections to a given source URL.
func (m *Mapper) getHostConnectionsTo(sourceURL *SourceURL) (*ConnectionsToFrom, error) {
	// Check for empty source URL host value first (only required field)
	if sourceURL.Host == "" {
		return nil, fmt.Errorf("source URL host is required")
	}

	var rows pgx.Rows

	// Get the host connections data from the database, using a different query depending on what source URL
	// data is provided (i.e. combinations of scheme, host, and path)
	if sourceURL.Scheme != "" && sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL scheme, host, and path are provided, use all three in the query
		sqlSelect := `select distinct referer_host, min(first_seen), max(last_seen) from data_mapper where destination_scheme = $1 and destination_host = $2 and destination_path = $3 group by referer_host order by referer_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Scheme != "" && sourceURL.Host != "" {
		// Source URL scheme and host are provided, use both in the query
		sqlSelect := `select distinct referer_host, min(first_seen), max(last_seen) from data_mapper where destination_scheme = $1 and destination_host = $2 group by referer_host  order by referer_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL host and path are provided, use both in the query
		sqlSelect := `select distinct referer_host, min(first_seen), max(last_seen) from data_mapper where destination_host = $1 and destination_path = $2 group by referer_host order by referer_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else {
		// Only source URL host is provided, use it in the query
		sqlSelect := `select distinct referer_host, min(first_seen), max(last_seen) from data_mapper where destination_host = $1 group by referer_host  order by referer_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	}

	// Ensure the rows are closed
	defer rows.Close()

	// Create a slice to hold the connections
	connections := make([]Connection, 0)

	// Get the count of rows returned
	count := 0
	for rows.Next() {
		count++

		// Get the data for the row
		var destinationHost string
		var firstSeen time.Time
		var lastSeen time.Time
		if scanErr := rows.Scan(&destinationHost, &firstSeen, &lastSeen); scanErr != nil {
			return nil, fmt.Errorf("unable to scan row: %w", scanErr)
		}

		// Add the data to the connections slice
		connections = append(connections, Connection{
			URL:       destinationHost,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		})
	}

	// Check for errors from iterating over rows
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unable to iterate over rows: %w", rowsErr)
	}

	// Return the data
	return &ConnectionsToFrom{
		Count:       count,
		Connections: connections,
	}, nil
}

// getHostConnectionsFrom gets the host data for connections from a given source URL.
func (m *Mapper) getHostConnectionsFrom(sourceURL *SourceURL) (*ConnectionsToFrom, error) {
	// Check for empty source URL host value first (only required field)
	if sourceURL.Host == "" {
		return nil, fmt.Errorf("source URL host is required")
	}

	var rows pgx.Rows

	// Get the host connections data from the database, using a different query depending on what source URL
	// data is provided (i.e. combinations of scheme, host, and path, with host being the only required value).
	if sourceURL.Scheme != "" && sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL scheme, host, and path are provided, use all three in the query
		sqlSelect := `select distinct destination_host, min(first_seen), max(last_seen) from data_mapper where referer_scheme = $1 and referer_host = $2 and referer_path = $3 group by destination_host order by destination_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Scheme != "" && sourceURL.Host != "" {
		// Source URL scheme and host are provided, use both in the query
		sqlSelect := `select distinct destination_host, min(first_seen), max(last_seen) from data_mapper where referer_scheme = $1 and referer_host = $2 group by destination_host order by destination_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL host and path are provided, use both in the query
		sqlSelect := `select distinct destination_host, min(first_seen), max(last_seen) from data_mapper where referer_host = $1 and referer_path = $2 group by destination_host order by destination_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else {
		// Only source URL host is provided, use it in the query
		sqlSelect := `select distinct destination_host, min(first_seen), max(last_seen) from data_mapper where referer_host = $1 group by destination_host order by destination_host;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	}

	// Ensure the rows are closed
	defer rows.Close()

	// Create a slice to hold the connections
	connections := make([]Connection, 0)

	// Get the count of rows returned
	count := 0
	for rows.Next() {
		count++

		// Get the data for the row
		var destinationHost string
		var firstSeen time.Time
		var lastSeen time.Time
		if scanErr := rows.Scan(&destinationHost, &firstSeen, &lastSeen); scanErr != nil {
			return nil, fmt.Errorf("unable to scan row: %w", scanErr)
		}

		// Add the data to the connections slice
		connections = append(connections, Connection{
			URL:       destinationHost,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		})
	}

	// Check for errors from iterating over rows
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unable to iterate over rows: %w", rowsErr)
	}

	// Return the data
	return &ConnectionsToFrom{
		Count:       count,
		Connections: connections,
	}, nil
}

// PathsDataAPIHandler handles requests to the mapper data API for all connecting paths (full URL,
// including scheme, host, and path) to and from a given URL.
// Only POST requests are allowed, as we need the source URL data in the request body.
func (m *Mapper) PathsDataAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests (or OPTIONS)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "POST")
		return
	} else if r.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	// Attempt to parse the source URL from the request
	reqBody, bodyCopy, bodyReadErr := internalHttp.ReadBody(r.Body)
	r.Body = bodyCopy
	if bodyReadErr != nil {
		http.Error(w, fmt.Sprintf("unable to read request body: %s", bodyReadErr.Error()), http.StatusInternalServerError)
		return
	}
	var sourceURL SourceURL
	if jsonUnMarshalErr := json.Unmarshal(reqBody, &sourceURL); jsonUnMarshalErr != nil {
		http.Error(w, fmt.Sprintf("unable to parse JSON request body into source URL object: %s", jsonUnMarshalErr.Error()), http.StatusInternalServerError)
		return
	}

	// Get the paths connections data from the database
	pathsData, pathsDataErr := m.getConnectingPaths(&sourceURL)
	if pathsDataErr != nil {
		http.Error(w, fmt.Sprintf("unable to get paths connections data: %s", pathsDataErr.Error()), http.StatusInternalServerError)
		return
	}

	// Return the data as JSON
	w.Header().Set("Content-Type", "application/json")
	if jsonMarshalErr := json.NewEncoder(w).Encode(pathsData); jsonMarshalErr != nil {
		http.Error(w, fmt.Sprintf("unable to encode paths connections data to JSON: %s", jsonMarshalErr.Error()), http.StatusInternalServerError)
		return
	}
}

// getConnectingPasts gets the paths data for connections from a given source URL.
// The source URL must include a host, but can optionally include a scheme and path.
func (m *Mapper) getConnectingPaths(sourceURL *SourceURL) (*ConnectionsOutput, error) {
	eg := new(errgroup.Group)

	// Get the connections to the source URL
	connectionsTo := new(ConnectionsToFrom)
	eg.Go(func() error {
		var err error
		connectionsTo, err = m.getPathConnectionsTo(sourceURL)
		if err != nil {
			return fmt.Errorf("unable to get connections to source URL: %w", err)
		}

		return nil
	})

	// Get the connections from the source URL
	connectionsFrom := new(ConnectionsToFrom)
	eg.Go(func() error {
		var err error
		connectionsFrom, err = m.getPathConnectionsFrom(sourceURL)
		if err != nil {
			return fmt.Errorf("unable to get connections from source URL: %w", err)
		}

		return nil
	})

	// Wait for the goroutines to finish
	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("unable to get connecting paths data: %w", err)
	}

	// Return the data
	return &ConnectionsOutput{
		SourceURL:       *sourceURL,
		ConnectionsTo:   *connectionsTo,
		ConnectionsFrom: *connectionsFrom,
	}, nil
}

// getPathConnectionsTo gets the paths data for connections to a given source URL.
// The source URL must include a host, but can optionally include a scheme and path.
func (m *Mapper) getPathConnectionsTo(sourceURL *SourceURL) (*ConnectionsToFrom, error) {
	// Check for empty source URL host value first (only required field)
	if sourceURL.Host == "" {
		return nil, fmt.Errorf("source URL host is required")
	}

	// Get the connections to the source URL from the database
	var rows pgx.Rows
	if sourceURL.Scheme != "" && sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL scheme, host and path are provided, use all in the query
		sqlSelect := `select distinct referer_scheme || '://' || referer_host || referer_path as referer_url, min(first_seen), max(last_seen) from data_mapper where destination_scheme = $1 and destination_host = $2 and destination_path = $3 and referer_host != '' group by referer_scheme, referer_host, referer_path order by referer_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Scheme != "" && sourceURL.Host != "" {
		// Source URL scheme and host are provided, use both in the query
		sqlSelect := `select distinct referer_scheme || '://' || referer_host || referer_path as referer_url, min(first_seen), max(last_seen) from data_mapper where destination_scheme = $1 and destination_host = $2 and referer_host != '' group by referer_scheme, referer_host, referer_path order by referer_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL host and path are provided, use both in the query
		sqlSelect := `select distinct referer_scheme || '://' || referer_host || referer_path as referer_url, min(first_seen), max(last_seen) from data_mapper where destination_host = $1 and destination_path = $2 and referer_host != '' group by referer_scheme, referer_host, referer_path order by referer_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else {
		// Source URL host is provided, use only host in the query
		sqlSelect := `select distinct referer_scheme || '://' || referer_host || referer_path as referer_url, min(first_seen), max(last_seen) from data_mapper where destination_host = $1 and referer_host != '' group by referer_scheme, referer_host, referer_path order by referer_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	}

	// Ensure the rows are closed
	defer rows.Close()

	// Count the rows returned
	count := 0

	// Get the connections to the source URL from the database
	connections := make([]Connection, 0)
	for rows.Next() {
		count++

		var refererURL string
		var firstSeen time.Time
		var lastSeen time.Time
		if scanErr := rows.Scan(&refererURL, &firstSeen, &lastSeen); scanErr != nil {
			return nil, fmt.Errorf("unable to scan row: %w", scanErr)
		}

		// Add the data to the connections slice
		connections = append(connections, Connection{
			URL:       refererURL,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		})
	}

	// Check for errors from iterating over rows
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unable to iterate over rows: %w", rowsErr)
	}

	// Return the connections to the source URL
	return &ConnectionsToFrom{
		Count:       count,
		Connections: connections,
	}, nil
}

// getPathConnectionsFrom gets the paths data for connections from a given source URL.
// The source URL must include a host, but can optionally include a scheme and path.
func (m *Mapper) getPathConnectionsFrom(sourceURL *SourceURL) (*ConnectionsToFrom, error) {
	// Check for empty source URL host value first (only required field)
	if sourceURL.Host == "" {
		return nil, fmt.Errorf("source URL host is required")
	}

	// Get the connections from the source URL from the database
	var rows pgx.Rows
	if sourceURL.Scheme != "" && sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL scheme, host and path are provided, use all in the query
		sqlSelect := `select distinct destination_scheme || '://' || destination_host || destination_path as destination_url, min(first_seen), max(last_seen) from data_mapper where referer_scheme = $1 and referer_host = $2 and referer_path = $3 group by destination_scheme, destination_host, destination_path order by destination_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Scheme != "" && sourceURL.Host != "" {
		// Source URL scheme and host are provided, use both in the query
		sqlSelect := `select distinct destination_scheme || '://' || destination_host || destination_path as destination_url, min(first_seen), max(last_seen) from data_mapper where referer_scheme = $1 and referer_host = $2 group by destination_scheme, destination_host, destination_path order by destination_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Scheme, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else if sourceURL.Host != "" && sourceURL.Path != "" {
		// Source URL host and path are provided, use both in the query
		sqlSelect := `select distinct destination_scheme || '://' || destination_host || destination_path as destination_url, min(first_seen), max(last_seen) from data_mapper where referer_host = $1 and referer_path = $2 group by destination_scheme, destination_host, destination_path order by destination_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host, sourceURL.Path)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	} else {
		// Source URL host is provided, use only host in the query
		sqlSelect := `select distinct destination_scheme || '://' || destination_host || destination_path as destination_url, min(first_seen), max(last_seen) from data_mapper where referer_host = $1 group by destination_scheme, destination_host, destination_path order by destination_url;`
		var queryErr error
		rows, queryErr = m.dbConnPool.Query(context.Background(), sqlSelect, sourceURL.Host)
		if queryErr != nil {
			return nil, fmt.Errorf("unable to query database: %w", queryErr)
		}
	}

	// Ensure the rows are closed
	defer rows.Close()

	// Count the rows returned
	count := 0

	// Get the connections from the source URL from the database
	connections := make([]Connection, 0)
	for rows.Next() {
		count++

		var destinationURL string
		var firstSeen time.Time
		var lastSeen time.Time
		if scanErr := rows.Scan(&destinationURL, &firstSeen, &lastSeen); scanErr != nil {
			return nil, fmt.Errorf("unable to scan row: %w", scanErr)
		}

		// Add the data to the connections slice
		connections = append(connections, Connection{
			URL:       destinationURL,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		})
	}

	// Check for errors from iterating over rows
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("unable to iterate over rows: %w", rowsErr)
	}

	// Return the connections from the source URL
	return &ConnectionsToFrom{
		Count:       count,
		Connections: connections,
	}, nil
}

// AllHostsGexf is an HTTP handler function that returns a GEXF file containing all hosts and their connections
// to the client.
func (m *Mapper) AllHostsGexf(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests (or OPTIONS)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	} else if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	}

	// Get all source and destination hosts from the database that were seen no more than 30 days ago
	sqlSelect := `with all_hosts as (select distinct referer_host as referer, destination_host as destination
						   from data_mapper
						   where last_seen > now() - interval '30 days')
		select referer, destination
		from all_hosts
		where referer != ''
		  and destination != ''
		  and referer != destination
		order by referer, destination;`
	rows, queryErr := m.dbConnPool.Query(r.Context(), sqlSelect)
	if queryErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", queryErr), http.StatusInternalServerError)
		return
	}

	// Create the GEXF host map structure
	gexfHostMap := gexf.CreateHostMapGexf()

	// Iterate through the results and add the connections to the GEXF host map structure
	for rows.Next() {
		var referer, destination string
		if scanErr := rows.Scan(&referer, &destination); scanErr != nil {
			http.Error(w, fmt.Sprintf("problem scanning hosts: %s", scanErr), http.StatusInternalServerError)
			return
		}
		gexfHostMap.AddConnection(referer, destination)
	}

	// Check for any errors
	if rowsErr := rows.Err(); rowsErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", rowsErr), http.StatusInternalServerError)
		return
	}

	// Set the content type
	w.Header().Set("Content-Type", "application/gexf+xml")

	// Set the filename
	w.Header().Set("Content-Disposition", "attachment; filename=hosts.gexf")

	// Write the GEXF host map structure to the response
	if _, writeErr := gexfHostMap.Write(w); writeErr != nil {
		http.Error(w, fmt.Sprintf("problem writing GEXF host map structure: %s", writeErr), http.StatusInternalServerError)
		return
	}
}

// HostTwoDegreesGexf is an HTTP handler function that returns a GEXF file to the client containing the
// connecting hosts from the provided host, including connections up to two degrees away.
func (m *Mapper) HostTwoDegreesGexf(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests (or OPTIONS)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	} else if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	}

	// Get the host from the query string
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}

	// Create the GEXF host map structure
	gexfHostMap := gexf.CreateHostMapGexf()

	// Query the database for all connecting hosts up to two degrees away from the provided host
	sqlSelect := `select referer_host, destination_host, degrees_of_separation from get_referer_destination_host_pairs_within_two_degrees($1);`
	rows, queryErr := m.dbConnPool.Query(r.Context(), sqlSelect, host)
	if queryErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", queryErr), http.StatusInternalServerError)
		return
	}

	// Iterate through the results and add the connections to the GEXF host map structure
	for rows.Next() {
		var referer, destination string
		var degreesOfSeparation int
		if scanErr := rows.Scan(&referer, &destination, &degreesOfSeparation); scanErr != nil {
			http.Error(w, fmt.Sprintf("problem scanning hosts: %s", scanErr), http.StatusInternalServerError)
			return
		}
		gexfHostMap.AddConnection(referer, destination)
	}

	// Check for any errors
	if rowsErr := rows.Err(); rowsErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", rowsErr), http.StatusInternalServerError)
		return
	}

	// Set the content type
	w.Header().Set("Content-Type", "application/gexf+xml")

	// Set the filename
	w.Header().Set("Content-Disposition", "attachment; filename=host_connections_two_degrees.gexf")

	// Write the GEXF host map structure to the response
	if _, writeErr := gexfHostMap.Write(w); writeErr != nil {
		http.Error(w, fmt.Sprintf("problem writing GEXF host map structure: %s", writeErr), http.StatusInternalServerError)
		return
	}
}

// HostsOneDegreeGexf is an HTTP handler function that returns a GEXF file to the client containing the
// connecting hosts from the provided list of hosts (comma-separated), including connections up to one degree away.
func (m *Mapper) HostsOneDegreeGexf(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests (or OPTIONS)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	} else if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	}

	// Get the hosts from the query string
	hosts := r.URL.Query().Get("hosts")
	if hosts == "" {
		http.Error(w, "hosts are required", http.StatusBadRequest)
		return
	}
	// Turn into a slice
	hostSlice := strings.Split(hosts, ",")

	// Create the GEXF host map structure
	gexfHostMap := gexf.CreateHostMapGexf()

	// Query the database for all connecting hosts up to one degree away from the provided hosts
	sqlSelect := `select ref_host, dest_host from get_connected_hosts($1);`
	rows, queryErr := m.dbConnPool.Query(r.Context(), sqlSelect, pq.Array(hostSlice))
	if queryErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", queryErr), http.StatusInternalServerError)
		return
	}

	// Iterate through the results and add the connections to the GEXF host map structure
	for rows.Next() {
		var referer, destination string
		if scanErr := rows.Scan(&referer, &destination); scanErr != nil {
			http.Error(w, fmt.Sprintf("problem scanning hosts: %s", scanErr), http.StatusInternalServerError)
			return
		}
		gexfHostMap.AddConnection(referer, destination)
	}

	// Check for any errors
	if rowsErr := rows.Err(); rowsErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", rowsErr), http.StatusInternalServerError)
		return
	}

	// Set the content type
	w.Header().Set("Content-Type", "application/gexf+xml")

	// Set the filename
	w.Header().Set("Content-Disposition", "attachment; filename=hosts.gexf")

	// Write the GEXF host map structure to the response
	if _, writeErr := gexfHostMap.Write(w); writeErr != nil {
		http.Error(w, fmt.Sprintf("problem writing GEXF host map structure: %s", writeErr), http.StatusInternalServerError)
		return
	}
}

// PathsAndConnectionsForHostsGexf is an HTTP handler function that returns a GEXF file to the client containing the
// paths and connections for the provided hosts.
func (m *Mapper) PathsAndConnectionsForHostsGexf(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests (or OPTIONS)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	} else if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Header().Set("Allow", "GET, OPTIONS")
		return
	}

	// Get the hosts from the query string
	hosts := r.URL.Query().Get("hosts")
	if hosts == "" {
		http.Error(w, "hosts are required", http.StatusBadRequest)
		return
	}
	// Turn into a slice
	hostSlice := strings.Split(hosts, ",")

	// Create the GEXF host map structure
	gexfHostMap := gexf.CreatePathHostsMapGexf()

	// Query the database for all connecting hosts up to one degree away from the provided hosts
	sqlSelect := `select source, destination from get_paths_and_connected_hosts($1) where source != destination;`
	rows, queryErr := m.dbConnPool.Query(r.Context(), sqlSelect, pq.Array(hostSlice))
	if queryErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", queryErr), http.StatusInternalServerError)
		return
	}

	// Iterate through the results and add the connections to the GEXF host map structure
	for rows.Next() {
		var referer, destination string
		if scanErr := rows.Scan(&referer, &destination); scanErr != nil {
			http.Error(w, fmt.Sprintf("problem scanning hosts: %s", scanErr), http.StatusInternalServerError)
			return
		}
		gexfHostMap.AddConnection(referer, destination)
	}

	// Check for any errors
	if rowsErr := rows.Err(); rowsErr != nil {
		http.Error(w, fmt.Sprintf("problem getting hosts: %s", rowsErr), http.StatusInternalServerError)
		return
	}

	// Close the rows
	rows.Close()

	// Query for the classification data for these hosts
	sqlClassificationSelect := `select concat(url_scheme, '://', url_host, url_path) as path, class from get_classifications_for_mapper_data($1);`
	classificationRows, classificationQueryErr := m.dbConnPool.Query(r.Context(), sqlClassificationSelect, pq.Array(hostSlice))
	if classificationQueryErr != nil {
		http.Error(w, fmt.Sprintf("problem getting classifications: %s", classificationQueryErr), http.StatusInternalServerError)
		return
	}

	// Iterate through the results and add the classifications to the GEXF host map structure
	for classificationRows.Next() {
		var path string
		var classification int
		if scanErr := classificationRows.Scan(&path, &classification); scanErr != nil {
			http.Error(w, fmt.Sprintf("problem scanning classifications: %s", scanErr), http.StatusInternalServerError)
			return
		}
		gexfHostMap.AddClassification(path, classification)
	}

	// Check for any errors
	if classificationRowsErr := classificationRows.Err(); classificationRowsErr != nil {
		http.Error(w, fmt.Sprintf("problem getting classifications: %s", classificationRowsErr), http.StatusInternalServerError)
		return
	}

	// Close the rows
	classificationRows.Close()

	// Set the content type
	w.Header().Set("Content-Type", "application/gexf+xml")

	// Set the filename
	w.Header().Set("Content-Disposition", "attachment; filename=paths_and_connections_for_hosts.gexf")

	// Write the GEXF host map
	if _, writeErr := gexfHostMap.Write(w); writeErr != nil {
		http.Error(w, fmt.Sprintf("problem writing GEXF host map structure: %s", writeErr), http.StatusInternalServerError)
		return
	}
}
