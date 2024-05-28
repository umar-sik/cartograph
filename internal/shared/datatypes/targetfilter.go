package datatypes

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// TargetFilter is the universal filtering language used to specify HTTP targets.
type TargetFilter struct {
	// Latest time to match (select data before this time).
	// Zero value is January 1, year 1, 00:00:00.000000000 UTC.
	Latest time.Time `json:"latest"`

	// Earliest time to match (select data after this time).
	// Zero value is January 1, year 1, 00:00:00.000000000 UTC.
	Earliest time.Time `json:"earliest"`

	// Set to "true" if this is an ignore rule set.
	Ignore bool `json:"ignore"`

	// Filter by hosts (case-insensitive; normalized to lowercase).
	Hosts []string `json:"hosts"`
	// Filter by the given URL paths (e.g. "/admin", "/get/config"; case-sensitive).
	// Includes cases where ANY of the given URL paths are found
	// (OR in boolean logic).
	URLPaths []string `json:"url_paths"`
	// Filter by HTTP response codes (e.g. "200", "300", "403", etc.).
	// Includes cases where ANY of the given response codes are found
	// (OR in boolean logic).
	RespCodes []string `json:"resp_codes"`
	// Filter by URL schemes (e.g. "http", "https", "file", "ssh"; case-insensitive,
	// normalized to lowercase).
	// Includes cases where ANY of the given URL schemes are found
	// (OR in boolean logic).
	URLSchemes []string `json:"url_schemes"`
	// Filter by HTTP request methods (e.g. "GET", "POST", "PUT", etc.; case-sensitive).
	// Includes cases where ANY of the given request methods are found
	// (OR in boolean logic).
	ReqMethods []string `json:"req_types"`
	// Filter by HTTP request parameter key-value pairs (case-sensitive).
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	ParamKeyValues map[string][]string `json:"param_key_values"`
	// Filter by header key-value pairs (case-insensitive) found in
	// HTTP requests.
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	HeaderKeyValuesReq map[string][]string `json:"header_key_values_req"`
	// Filter by header key-value pairs (case-insensitive) found in
	// HTTP responses.
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	HeaderKeyValuesResp map[string][]string `json:"header_key_values_resp"`
	// Filter by cookie key-value pairs (case-insensitive) found in
	// HTTP requests and responses.
	// Includes cases where ANY of the given key-value pairs are found
	// (OR in boolean logic).
	CookieKeyValues map[string][]string `json:"cookie_key_values"`
}

// ToTargetIgnore returns a target/ignore data structure based on the data in the target filter object.
// If an error is returned, the given target/ignore list will be invalid.
func (tf TargetFilter) ToTargetIgnore() (ti *TargetIgnore, err error) {
	// Create an error group, which allows us to stop all goroutines when one error occurs
	eg := new(errgroup.Group)

	// Initialize a blank target/ignore object, ensuring all fields are initialized (maps, in particular,
	// as they can lead to fatal errors when trying to add or remove from them when uninitialized).
	ti = &TargetIgnore{
		IsIgnore:            false,
		Latest:              time.Time{},
		Earliest:            time.Time{},
		Hosts:               make(map[string]*regexp.Regexp),
		URLPaths:            make(map[string]*regexp.Regexp),
		RespCodes:           make(map[string]*regexp.Regexp),
		URLSchemes:          make(map[string]*regexp.Regexp),
		ReqMethods:          make(map[string]*regexp.Regexp),
		ParamKeyValues:      make(map[string]*RegexKeyValue),
		HeaderKeyValuesReq:  make(map[string]*RegexKeyValue),
		HeaderKeyValuesResp: make(map[string]*RegexKeyValue),
		CookieKeyValues:     make(map[string]*RegexKeyValue),
	}

	// Hosts
	eg.Go(func() error {
		for _, domain := range tf.Hosts {
			// Trim whitespace
			domain = strings.TrimSpace(domain)

			// Convert to lowercase.
			// RFC 7230, section 2.7.3: "The scheme and host are case-insensitive and normally provided in lowercase;
			// all other components are compared in a case-sensitive manner."
			domain = strings.ToLower(domain)

			// Convert to regular expression
			d := convertToRegexString(domain)
			regex, regexErr := regexp.Compile("(?i)^" + d + "$")
			if regexErr != nil {
				return fmt.Errorf("unable to compile regular expression for domain string %q: %w", domain, regexErr)
			}

			// Add to target or ignore list
			ti.Hosts[domain] = regex
		}

		return nil
	})

	// URL paths
	eg.Go(func() error {
		for _, urlPath := range tf.URLPaths {
			// Trim whitespace
			urlPath = strings.TrimSpace(urlPath)

			// Convert to regular expression
			// This search is case-sensitive, to comply with RFC 7230.
			// RFC 7230, section 2.7.3: "The scheme and host are case-insensitive and normally provided in lowercase;
			// all other components are compared in a case-sensitive manner."
			up := convertToRegexString(urlPath)
			regex, regexErr := regexp.Compile("^" + up + "$")
			if regexErr != nil {
				return fmt.Errorf("unable to compile regular expression for URL path string %q: %w", urlPath, regexErr)
			}

			// Add to target or ignore list
			ti.Hosts[urlPath] = regex
		}

		return nil
	})

	// Response codes
	eg.Go(func() error {
		for _, respCode := range tf.RespCodes {
			// Trim whitespace
			respCode = strings.TrimSpace(respCode)

			// Ensure the response code is a valid number
			if _, convErr := strconv.Atoi(respCode); convErr != nil {
				return fmt.Errorf("invalid response code given (%q), must be valid integer: %w", respCode, convErr)
			}

			// Convert to regular expression
			rc := convertToRegexString(respCode)
			regex, regexErr := regexp.Compile("^" + rc + "$")
			if regexErr != nil {
				return fmt.Errorf("unable to compile regular expression for response code string %q: %w", respCode, regexErr)
			}

			// Add to target or ignore list
			ti.RespCodes[respCode] = regex
		}

		return nil
	})

	// URL schemes
	eg.Go(func() error {
		for _, urlScheme := range tf.URLSchemes {
			// Trim whitespace
			urlScheme = strings.TrimSpace(urlScheme)

			// Convert to lowercase.
			// RFC 7230, section 2.7.3: "The scheme and host are case-insensitive and normally provided in lowercase;
			// all other components are compared in a case-sensitive manner."
			urlScheme = strings.ToLower(urlScheme)

			// Convert to regular expression
			uc := convertToRegexString(urlScheme)
			regex, regexErr := regexp.Compile("(?i)^" + uc + "$")
			if regexErr != nil {
				return fmt.Errorf("unable to compile regular expression for URL scheme string %q: %w", urlScheme, regexErr)
			}

			// Add to target or ignore list
			ti.URLSchemes[urlScheme] = regex
		}

		return nil
	})

	// HTTP request methods
	eg.Go(func() error {
		for _, reqMethod := range tf.ReqMethods {
			// Trim whitespace
			reqMethod = strings.TrimSpace(reqMethod)

			// Convert to uppercase, for more uniform comparison.
			// RFC 7231, section 4.1: "By convention, standardized methods are defined in
			// all-uppercase US-ASCII letters."
			// *UPDATE*: We won't enforce how the user stores the method names, as doing so would conflict with the
			// case-sensitive search performed on them, and restrict any lowercase methods from being used
			// in target filter rules.
			// reqMethod = strings.ToUpper(reqMethod)

			// Convert to regular expression
			// We use a case-sensitive search.
			// RFC 7231, section 4.1: "The method token is case-sensitive because it might be
			//   used as a gateway to object-based systems with case-sensitive method
			//   names."
			rm := convertToRegexString(reqMethod)
			regex, regexErr := regexp.Compile("^" + rm + "$")
			if regexErr != nil {
				return fmt.Errorf("unable to compile regular expression for HTTP request method string %q: %w", reqMethod, regexErr)
			}

			// Add to target or ignore list
			ti.ReqMethods[reqMethod] = regex
		}

		return nil
	})

	// HTTP parameter key:value pairs
	eg.Go(func() error {
		for key, values := range tf.ParamKeyValues {
			// Create RegexKeyValue structure
			rkv := &RegexKeyValue{
				Values: make(map[string]*regexp.Regexp, len(values)),
			}

			// Trim whitespace
			key = strings.TrimSpace(key)

			// Convert to regular expression
			// This search is case-sensitive, to comply with RFC 7230.
			// RFC 7230, section 2.7.3: "The scheme and host are case-insensitive and normally provided in lowercase;
			// all other components are compared in a case-sensitive manner."
			k := convertToRegexString(key)
			regexK, regexKErr := regexp.Compile("(?m)^" + k + "$")
			if regexKErr != nil {
				return fmt.Errorf("unable to compile regular expression for HTTP parameter key string %q: %w", key, regexKErr)
			}

			// Add key to the RegexKeyValue structure
			rkv.KeyRegex = regexK

			// Iterate through the values
			for _, value := range values {
				// Trim whitespace
				value = strings.TrimSpace(value)

				// Convert to regular expression
				// This search is case-sensitive, to comply with RFC 7230.
				// RFC 7230, section 2.7.3: "The scheme and host are case-insensitive and normally provided in lowercase;
				// all other components are compared in a case-sensitive manner."
				v := convertToRegexString(value)
				regexV, regexVErr := regexp.Compile("(?m)^" + v + "$")
				if regexVErr != nil {
					return fmt.Errorf("unable to compile regular expression for HTTP parameter value string %q: %w", value, regexVErr)
				}

				// Add value to RegexKeyValue structure
				rkv.Values[value] = regexV
			}

			// Add to target or ignore list
			ti.ParamKeyValues[key] = rkv
		}

		return nil
	})

	// HTTP request header key:value pairs
	eg.Go(func() error {
		for key, values := range tf.HeaderKeyValuesReq {
			// Create RegexKeyValue structure
			rkv := &RegexKeyValue{
				Values: make(map[string]*regexp.Regexp, len(values)),
			}

			// Trim whitespace
			key = strings.TrimSpace(key)

			// Convert to regular expression.
			// This search is case-insensitive, to comply with RFC 7230.
			// RFC 7230, section 3.2: "Each header field consists of a case-insensitive field name followed by a
			// colon (":"), optional leading whitespace, the field value, and optional trailing whitespace."
			k := convertToRegexString(key)
			regexK, regexKErr := regexp.Compile("(?im)^" + k + "$")
			if regexKErr != nil {
				return fmt.Errorf("unable to compile regular expression for HTTP request header key string %q: %w", key, regexKErr)
			}

			// Add key to the RegexKeyValue structure
			rkv.KeyRegex = regexK

			// Iterate through the values
			for _, value := range values {
				// Trim whitespace
				value = strings.TrimSpace(value)

				// Convert to regular expression.
				// This search is case-insensitive, to comply with RFC 7230.
				// RFC 7230, section 3.2: "Each header field consists of a case-insensitive field name followed by a
				// colon (":"), optional leading whitespace, the field value, and optional trailing whitespace."
				v := convertToRegexString(value)
				regexV, regexVErr := regexp.Compile("(?im)^" + v + "$")
				if regexVErr != nil {
					return fmt.Errorf("unable to compile regular expression for HTTP request header value string %q: %w", value, regexVErr)
				}

				// Add value to RegexKeyValue structure
				rkv.Values[value] = regexV
			}

			// Add to target or ignore list
			ti.HeaderKeyValuesReq[key] = rkv
		}

		return nil
	})

	// HTTP response header key:value pairs
	eg.Go(func() error {
		for key, values := range tf.HeaderKeyValuesResp {
			// Create RegexKeyValue structure
			rkv := &RegexKeyValue{
				Values: make(map[string]*regexp.Regexp, len(values)),
			}

			// Trim whitespace
			key = strings.TrimSpace(key)

			// Convert to regular expression.
			// This search is case-insensitive, to comply with RFC 7230.
			// RFC 7230, section 3.2: "Each header field consists of a case-insensitive field name followed by a
			// colon (":"), optional leading whitespace, the field value, and optional trailing whitespace."
			k := convertToRegexString(key)
			regexK, regexKErr := regexp.Compile("(?im)^" + k + "$")
			if regexKErr != nil {
				return fmt.Errorf("unable to compile regular expression for HTTP response header key string %q: %w", key, regexKErr)
			}

			// Add key to the RegexKeyValue structure
			rkv.KeyRegex = regexK

			// Iterate through the values
			for _, value := range values {
				// Trim whitespace
				value = strings.TrimSpace(value)

				// Convert to regular expression.
				// This search is case-insensitive, to comply with RFC 7230.
				// RFC 7230, section 3.2: "Each header field consists of a case-insensitive field name followed by a
				// colon (":"), optional leading whitespace, the field value, and optional trailing whitespace."
				v := convertToRegexString(value)
				regexV, regexVErr := regexp.Compile("(?im)^" + v + "$")
				if regexVErr != nil {
					return fmt.Errorf("unable to compile regular expression for HTTP response header value string %q: %w", value, regexVErr)
				}

				// Add value to RegexKeyValue structure
				rkv.Values[value] = regexV
			}

			// Add to target or ignore list
			ti.HeaderKeyValuesResp[key] = rkv
		}

		return nil
	})

	// HTTP cookies key:value pairs
	eg.Go(func() error {
		for key, values := range tf.CookieKeyValues {
			// Create RegexKeyValue structure
			rkv := &RegexKeyValue{
				Values: make(map[string]*regexp.Regexp, len(values)),
			}

			// Trim whitespace
			key = strings.TrimSpace(key)

			// Convert to regular expression.
			// This search is case-insensitive, to comply with RFC 7230.
			// RFC 7230, section 3.2: "Each header field consists of a case-insensitive field name followed by a
			// colon (":"), optional leading whitespace, the field value, and optional trailing whitespace."
			// (Cookies are sent and set via headers)
			k := convertToRegexString(key)
			regexK, regexKErr := regexp.Compile("(?im)^" + k + "$")
			if regexKErr != nil {
				return fmt.Errorf("unable to compile regular expression for HTTP cookie key string %q: %w", key, regexKErr)
			}

			// Add key to the RegexKeyValue structure
			rkv.KeyRegex = regexK

			// Iterate through the values
			for _, value := range values {
				// Trim whitespace
				value = strings.TrimSpace(value)

				// Convert to regular expression.
				// This search is case-insensitive, to comply with RFC 7230.
				// RFC 7230, section 3.2: "Each header field consists of a case-insensitive field name followed by a
				// colon (":"), optional leading whitespace, the field value, and optional trailing whitespace."
				// (Cookies are sent and set via headers)
				v := convertToRegexString(value)
				regexV, regexVErr := regexp.Compile("(?im)^" + v + "$")
				if regexVErr != nil {
					return fmt.Errorf("unable to compile regular expression for HTTP cookie value string %q: %w", value, regexVErr)
				}

				// Add value to RegexKeyValue structure
				rkv.Values[value] = regexV
			}

			// Add to target or ignore list
			ti.CookieKeyValues[key] = rkv
		}

		return nil
	})

	// Ignored target
	ti.IsIgnore = tf.Ignore

	// Latest time
	ti.Latest = tf.Latest

	// Earliest time
	ti.Earliest = tf.Earliest

	// Wait for goroutines and save the first error, if any
	if err = eg.Wait(); err != nil {
		return nil, err
	}

	return
}

// ToLoggerRegexFilter converts the given target filter object to a logger regex filter object, which
// is used to fetch data from the data_logger database table using a stored procedure.
func (tf *TargetFilter) ToLoggerRegexFilter() LoggerRegexFilter {
	// TODO: Complete this when needed.

	return LoggerRegexFilter{}
}

// convertToRegexString converts the given input string to a regex-compatible string, including the conversion
// of the wildcard characters ("***").
func convertToRegexString(input string) (output string) {
	// Escape all regular expression metacharacters.
	output = regexp.QuoteMeta(input)

	// Convert wildcard characters
	output = strings.ReplaceAll(output, `\*\*\*`, `.*`)

	return
}

// TargetFilterSimple is the universal filtering language used to specify HTTP targets, limited to host values only.
type TargetFilterSimple struct {
	// Set to "true" if this is an ignore rule set.
	Ignore bool `json:"ignore"`

	// Filter by hosts (case-insensitive; normalized to lowercase).
	Hosts []string `json:"hosts"`
}

// ToTargetIgnoreSimple returns a simple target/ignore data structure based on the data in the simple target filter
// object.
// If an error is returned, the given target/ignore list will be invalid.
func (tfs TargetFilterSimple) ToTargetIgnoreSimple() (tis *TargetIgnoreSimple, err error) {
	// Initialize a blank simple target/ignore object, ensuring all fields are initialized (maps, in particular,
	// as they can lead to fatal errors when trying to add or remove from them when uninitialized).
	tis = &TargetIgnoreSimple{
		IsIgnore: tfs.Ignore,
		Hosts:    make(map[string]*regexp.Regexp),
	}

	// Convert hosts
	for _, host := range tfs.Hosts {
		// Trim whitespace
		host = strings.TrimSpace(host)

		// Convert to lowercase.
		// RFC 7230, section 2.7.3: "The scheme and host are case-insensitive and normally provided in lowercase;
		// all other components are compared in a case-sensitive manner."
		host = strings.ToLower(host)

		// Convert to regular expression
		d := convertToRegexString(host)
		regex, regexErr := regexp.Compile("(?i)^" + d + "$")
		if regexErr != nil {
			return nil, fmt.Errorf("unable to compile regular expression for host string %q: %w", host, regexErr)
		}

		// Add to target or ignore list
		tis.Hosts[host] = regex
	}

	return tis, nil
}
