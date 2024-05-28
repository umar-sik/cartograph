package datatypes

import (
	"time"
)

// LoggerRegexFilter is used to query logger data from a stored procedure in the database, using regex
// values to compare against.
type LoggerRegexFilter struct {
	// Select data starting from this time.
	// Zero value is set to the current time.
	Latest time.Time

	// Earliest time to match (select data after this time).
	// Zero value is January 1, year 1, 00:00:00.000000000 UTC.
	Earliest time.Time

	// Set to "true" if this is an ignore rule set.
	Ignore bool

	// Filter by hosts (case-insensitive; normalized to lowercase).
	Hosts []string
	// Filter by the given URL paths (e.g. "/admin", "/get/config"; case-sensitive).
	// Includes cases where ANY of the given URL paths are found
	// (OR in boolean logic).
	URLPaths []string
	// Filter by HTTP response codes (e.g. 200, 300, 403, etc.).
	// Includes cases where ANY of the given response codes are found
	// (OR in boolean logic).
	RespCodes []int
	// Filter by URL schemes (e.g. "http", "https", "file", "ssh"; case-insensitive,
	// normalized to lowercase).
	// Includes cases where ANY of the given URL schemes are found
	// (OR in boolean logic).
	URLSchemes []string
	// Filter by HTTP request methods (e.g. "GET", "POST", "PUT", etc.; case-sensitive).
	// Includes cases where ANY of the given request methods are found
	// (OR in boolean logic).
	ReqMethods []string
	// Filter by HTTP request parameter key-value pairs (case-sensitive).
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	ParamKeyValues []string
	// Filter by header key-value pairs (case-insensitive) found in
	// HTTP requests.
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	HeaderKeyValuesReq []string
	// Filter by header key-value pairs (case-insensitive) found in
	// HTTP responses.
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	HeaderKeyValuesResp []string
	// Filter by cookie key-value pairs (case-insensitive) found in
	// HTTP requests and responses.
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	CookieKeyValues []string
}
