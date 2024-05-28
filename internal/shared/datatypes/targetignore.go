package datatypes

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RegexKeyValue represents a key:value pairing with compiled regular expressions.
// This is helpful in the case of the TargetIgnore structure, where we have some fields (e.g. ParamKeyValues)
// that require key:value pair matching.
type RegexKeyValue struct {
	// The compiled regular expression for this key
	KeyRegex *regexp.Regexp

	// Values matched to this key, mapping the target filter value to the regular expression value
	Values map[string]*regexp.Regexp
}

// TargetIgnore is a data structure for target or ignore settings, using easily comparable data types.
type TargetIgnore struct {
	// Set to true when the list is an ignore list
	IsIgnore bool

	// Latest time to match (target data before this time).
	// Zero value is January 1, year 1, 00:00:00.000000000 UTC.
	Latest time.Time

	// Earliest time to match (target data after this time).
	// Zero value is January 1, year 1, 00:00:00.000000000 UTC.
	Earliest time.Time

	// Hosts to target, mapping the target filter value to the regular expression value
	Hosts map[string]*regexp.Regexp

	// URL paths to target, mapping the target filter value to the regular expression value
	URLPaths map[string]*regexp.Regexp

	// Response codes to target, mapping the target filter value to the regular expression value
	RespCodes map[string]*regexp.Regexp

	// URL schemes to target, mapping the target filter value to the regular expression value
	URLSchemes map[string]*regexp.Regexp

	// HTTP request methods (e.g. "GET", "POST", etc.) to target, mapping the target filter value
	// to the regular expression value
	ReqMethods map[string]*regexp.Regexp

	// HTTP parameter key:value pairs, mapping the target filter value for the key to the RegexKeyValue
	// struct holding both the value strings and the compiled regular expressions for the key and the values
	ParamKeyValues map[string]*RegexKeyValue

	// HTTP request header key:value pairs, mapping the target filter value for the key to the RegexKeyValue
	// struct holding both the value strings and the compiled regular expressions for the key and the values
	HeaderKeyValuesReq map[string]*RegexKeyValue

	// HTTP response header key:value pairs, mapping the target filter value for the key to the RegexKeyValue
	// struct holding both the value strings and the compiled regular expressions for the key and the values
	HeaderKeyValuesResp map[string]*RegexKeyValue

	// HTTP cookies key:value pairs, mapping the target filter value for the key to the RegexKeyValue
	// struct holding both the value strings and the compiled regular expressions for the key and the values
	CookieKeyValues map[string]*RegexKeyValue
}

// MatchesReqResp returns true if a match was found in the entire TargetIgnore data structure
// when comparing to the given HttpReqResp structure.
//
// NOTE: *ALL* set rule set fields must match for it to be considered a valid match. If a rule set field
// is not configured, then it will count as an automatic match, as the default field value is to match anything ("***").
//
// Each field is compared in a separate goroutine for speed and concurrency, and if
// any of the TargetIgnore fields do *not* match the given HttpReqResp structure,
// then this method returns false.
//
// NOTE: Caller must ensure that HttpReqResp object is complete, as we check all fields in this matching method. We do not
// perform that check here, in order to ensure the most performance possible.
func (ti *TargetIgnore) MatchesReqResp(httpReqResp *HttpReqResp) (matches bool) {
	var fieldsToCheck, fieldsMatched int

	// Set up channels to listen for if a match was found on a particular target/ignore rule set
	// data point.
	chanMatchFound := make(chan struct{}, 10)

	// Ensure we can cancel all match checks if one found no match, as matches must match all set fields to be valid.
	ctx, cancel := context.WithCancel(context.Background())

	// Domain check
	fieldsToCheck++
	go func() {
		// Check for empty domain target value, indicating no check is needed (default is to match anything).
		if len(ti.Hosts) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		// Ensure that port value is removed, if present
		domain, _, _ := strings.Cut(httpReqResp.Request.Url.Host, ":")

		// Check for matching domain
		for _, regexDomain := range ti.Hosts {
			if regexDomain.MatchString(domain) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match is found, which means we will automatically cancel our search everywhere
		cancel()
	}()

	// URL path check
	fieldsToCheck++
	go func() {
		// Check for empty path target value, indicating no check is needed (default is to match anything).
		if len(ti.URLPaths) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		path := httpReqResp.Request.Url.Path

		// Check for matching path
		for _, regexPath := range ti.URLPaths {
			if regexPath.MatchString(path) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match is found, which means we will automatically cancel our search everywhere
		cancel()
	}()

	// Response code check
	fieldsToCheck++
	go func() {
		// Check for empty response code target value, indicating no check is needed (default is to match anything).
		if len(ti.RespCodes) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		respCode := strconv.Itoa(httpReqResp.Response.StatusCode)

		// Check for matching response code
		for _, regexRespCode := range ti.RespCodes {
			if regexRespCode.MatchString(respCode) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match is found, which means we will automatically cancel our search everywhere
		cancel()
	}()

	// URL scheme check
	fieldsToCheck++
	go func() {
		// Check for empty URL scheme target value, indicating no check is needed (default is to match anything).
		if len(ti.URLSchemes) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		urlScheme := httpReqResp.Request.Url.Scheme

		// We are not converting to lowercase, as go's URL package does this already.
		// urlScheme = strings.ToLower(urlScheme)

		// Check for matching URL scheme
		for _, regexURLScheme := range ti.URLSchemes {
			if regexURLScheme.MatchString(urlScheme) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match is found, which means we will automatically cancel our search everywhere
		cancel()
	}()

	// HTTP request method check
	fieldsToCheck++
	go func() {
		// Check for empty request method target value, indicating no check is needed (default is to match anything).
		if len(ti.ReqMethods) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		reqMethod := httpReqResp.Request.Method

		// We are not converting to uppercase, as it should already be sent in uppercase as per RFC 7231.
		// reqMethod = strings.ToUpper(reqMethod)

		// Check for matching request method
		for _, regexReqMethod := range ti.ReqMethods {
			if regexReqMethod.MatchString(reqMethod) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match is found, which means we will automatically cancel our search everywhere
		cancel()
	}()

	// HTTP parameters key:value pair check
	fieldsToCheck++
	go func() {
		// Check for empty parameter key:value target value, indicating no check is needed (default is
		// to match anything).
		if len(ti.ParamKeyValues) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		fieldKeyValues := httpReqResp.Request.Url.Query()

		// If there are no parameter keys or values, then they won't match our rules, which *do* contain
		// entries for parameter key:value pairs.
		if len(fieldKeyValues) == 0 {
			cancel()
			return
		}

		// Channels for inner concurrency
		chanInnerMatchFound := make(chan struct{}, 1)
		chanInnerDone := make(chan struct{}, 1)

		// Sentinel values that will let us know if we've finished checking all inner field values
		innerFieldsToCheck := len(fieldKeyValues)
		var innerFieldsChecked int

		// Regex keys
		for _, rkv := range ti.ParamKeyValues {
			// Field keys
			for fieldKeys, fieldValues := range fieldKeyValues {
				if rkv.KeyRegex.MatchString(fieldKeys) {
					// Given the time complexity involved, we will split each key set out to a separate goroutine
					go func(rValues map[string]*regexp.Regexp, fValues []string) {
						// Ensure this goroutine is marked as done when completing
						defer func() { chanInnerDone <- struct{}{} }()

						// Regex values
						for _, rValue := range rValues {
							// Field values
							for _, fValue := range fValues {
								if rValue.MatchString(fValue) {
									// Value match found
									chanInnerMatchFound <- struct{}{}
									return
								}
							}
						}
					}(rkv.Values, fieldValues)
				}
			}
		}

		// Listen for the completion of inner goroutines
		for {
			select {
			case <-chanInnerDone:
				// One key set loop complete
				innerFieldsChecked++
				if innerFieldsToCheck == innerFieldsChecked {
					// Checked all fields, but no match was found
					cancel()
					return
				}
			case <-chanInnerMatchFound:
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}
	}()

	// HTTP request header key:value pair check
	fieldsToCheck++
	go func() {
		// Check for empty request header key:value target value, indicating no check is needed (default is
		// to match anything).
		if len(ti.HeaderKeyValuesReq) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		fieldKeyValues := httpReqResp.Request.Header

		// If there are no request header keys or values, then they won't match our rules, which *do* contain
		// entries for request header key:value pairs.
		if len(fieldKeyValues) == 0 {
			cancel()
			return
		}

		// Channels for inner concurrency
		chanInnerMatchFound := make(chan struct{}, 1)
		chanInnerDone := make(chan struct{}, 1)

		// Sentinel values that will let us know if we've finished checking all inner field values
		var innerFieldsToCheck, innerFieldsChecked int

		// Regex keys
		for _, rkv := range ti.HeaderKeyValuesReq {
			// Field keys
			for fieldKeys, fieldValues := range fieldKeyValues {
				if rkv.KeyRegex.MatchString(fieldKeys) {

					// Given the time complexity involved, we will split each key set out to a separate goroutine
					innerFieldsToCheck++
					go func(rValues map[string]*regexp.Regexp, fValues []string) {
						// Ensure this goroutine is marked as done when completing
						defer func() { chanInnerDone <- struct{}{} }()

						// Regex values
						for _, rValue := range rValues {
							// Field values
							for _, fValue := range fValues {
								if rValue.MatchString(fValue) {
									// Value match found
									chanInnerMatchFound <- struct{}{}
									return
								}
							}
						}
					}(rkv.Values, fieldValues)
				}
			}
		}

		// Listen for the completion of inner goroutines
		for {
			select {
			case <-chanInnerDone:
				// One key set loop complete
				innerFieldsChecked++
				if innerFieldsToCheck == innerFieldsChecked {
					// Checked all fields, but no match was found
					cancel()
					return
				}
			case <-chanInnerMatchFound:
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}
	}()

	// HTTP response header key:value pair check
	fieldsToCheck++
	go func() {
		// Check for empty response header key:value target value, indicating no check is needed (default is
		// to match anything).
		if len(ti.HeaderKeyValuesResp) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		fieldKeyValues := httpReqResp.Response.Header

		// If there are no response header keys or values, then they won't match our rules, which *do* contain
		// entries for response header key:value pairs.
		if len(fieldKeyValues) == 0 {
			cancel()
			return
		}

		// Channels for inner concurrency
		chanInnerMatchFound := make(chan struct{}, 1)
		chanInnerDone := make(chan struct{}, 1)

		// Sentinel values that will let us know if we've finished checking all inner field values
		var innerFieldsToCheck, innerFieldsChecked int

		// Regex keys
		for _, rkv := range ti.HeaderKeyValuesResp {
			// Field keys
			for fieldKeys, fieldValues := range fieldKeyValues {
				if rkv.KeyRegex.MatchString(fieldKeys) {

					// Given the time complexity involved, we will split each key set out to a separate goroutine
					innerFieldsToCheck++
					go func(rValues map[string]*regexp.Regexp, fValues []string) {
						// Ensure this goroutine is marked as done when completing
						defer func() { chanInnerDone <- struct{}{} }()

						// Regex values
						for _, rValue := range rValues {
							// Field values
							for _, fValue := range fValues {
								if rValue.MatchString(fValue) {
									// Value match found
									chanInnerMatchFound <- struct{}{}
									return
								}
							}
						}
					}(rkv.Values, fieldValues)
				}
			}
		}

		// Listen for the completion of inner goroutines
		for {
			select {
			case <-chanInnerDone:
				// One key set loop complete
				innerFieldsChecked++
				if innerFieldsToCheck == innerFieldsChecked {
					// Checked all fields, but no match was found
					cancel()
					return
				}
			case <-chanInnerMatchFound:
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}
	}()

	// HTTP cookies key:value pair check
	fieldsToCheck++
	go func() {
		// Check for empty cookie key:value target value, indicating no check is needed (default is
		// to match anything).
		if len(ti.CookieKeyValues) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		// Append cookie values together from request and response
		fieldKeyValues := httpReqResp.Request.Cookies
		fieldKeyValues = append(fieldKeyValues, httpReqResp.Response.Cookies...)

		// If there are no cookie keys or values, then they won't match our rules, which *do* contain
		// entries for cookie key:value pairs.
		if len(fieldKeyValues) == 0 {
			cancel()
			return
		}

		// Channels for inner concurrency
		chanInnerMatchFound := make(chan struct{}, 1)
		chanInnerDone := make(chan struct{}, 1)

		// Sentinel values that will let us know if we've finished checking all inner field values
		var innerFieldsToCheck, innerFieldsChecked int

		// Regex keys
		for _, rkv := range ti.CookieKeyValues {
			// Field keys
			for _, cookie := range fieldKeyValues {
				if rkv.KeyRegex.MatchString(cookie.Name) {

					// Given the time complexity involved, we will split each key set out to a separate goroutine
					innerFieldsToCheck++
					go func(rValues map[string]*regexp.Regexp, fValue string) {
						// Ensure this goroutine is marked as done when completing
						defer func() { chanInnerDone <- struct{}{} }()

						// Regex values
						for _, rValue := range rValues {
							// Field value
							if rValue.MatchString(fValue) {
								// Value match found
								chanInnerMatchFound <- struct{}{}
								return
							}
						}
					}(rkv.Values, cookie.Value)
				}
			}
		}

		// Listen for the completion of inner goroutines
		for {
			select {
			case <-chanInnerDone:
				// One key set loop complete
				innerFieldsChecked++
				if innerFieldsToCheck == innerFieldsChecked {
					// Checked all fields, but no match was found
					cancel()
					return
				}
			case <-chanInnerMatchFound:
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}
	}()

	// Earliest time check
	fieldsToCheck++
	go func() {
		// Check for empty time value, indicating no check is needed (default is to match anything).
		if ti.Earliest.IsZero() {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		// Check if request was sent after this time
		if httpReqResp.Request.Timestamp.After(ti.Earliest) {
			// Match found
			chanMatchFound <- struct{}{}
			return
		}

		// Request was sent before this time, thus not a match
		cancel()
	}()

	// Latest time check
	fieldsToCheck++
	go func() {
		// Check for empty time value, indicating no check is needed (default is to match anything).
		if ti.Latest.IsZero() {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		// Check if request was sent before this time
		if httpReqResp.Request.Timestamp.Before(ti.Latest) {
			// Match found
			chanMatchFound <- struct{}{}
			return
		}

		// Request was sent after this time, thus not a match
		cancel()
	}()

	// Listen for completion of all goroutines before returning
	for {
		select {
		case <-chanMatchFound:
			// Match found
			fieldsMatched++
			if fieldsToCheck == fieldsMatched {
				// All fields have been checked without a match not being found;
				// thus, matches were found for all fields.
				return true
			}
		case <-ctx.Done():
			// No match found in any one single data point for this ruleset, which means that this entire rule set
			// does not match (all or nothing).
			return false
		}
	}
}

// MapperMatches checks whether the given referer or destination URL matches the target/ignore rule, for use with
// the mapper plugin, where we only have the referer and destination URLs to check.
//
// The mapper plugin rules must match either the referer or destination URL, or both, to be considered a match.
func (ti *TargetIgnore) MapperMatches(referredData *ReferrerData) bool {
	if referredData.Referer.String() == "" {
		// No referer URL, so check only the destination URL.
		// This is valid, if the destination was directly browsed to.
		return ti.mapperMatchesURL(referredData.Destination)
	}

	return ti.mapperMatchesURL(referredData.Referer) || ti.mapperMatchesURL(referredData.Destination)
}

// mapperMatchesURL checks whether the given URL matches the target/ignore rule, for use with the mapper plugin.
// Only the domain and path are checked.
func (ti *TargetIgnore) mapperMatchesURL(u url.URL) bool {
	var fieldsToCheck, fieldsMatched int

	// Set up channels to listen for if a match was found on a particular target/ignore rule set
	// data point.
	chanMatchFound := make(chan struct{}, 10)

	// Ensure we can cancel all match checks if one found no match, as matches must match all set fields to be valid.
	ctx, cancel := context.WithCancel(context.Background())

	// Domain check
	fieldsToCheck++
	go func() {
		// Check for empty domain value, indicating no check is needed (default is to match anything).
		if len(ti.Hosts) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		// Ensure the port value is removed, if present
		domain, _, _ := strings.Cut(u.Host, ":")

		// Check for matching domain
		for _, regexDomain := range ti.Hosts {
			if regexDomain.MatchString(domain) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match found
		cancel()
	}()

	// URL path check
	fieldsToCheck++
	go func() {
		// Check for empty URL path value, indicating no check is needed (default is to match anything).
		if len(ti.URLPaths) == 0 {
			// Automatically mark as a match
			chanMatchFound <- struct{}{}
			return
		}

		// Check for matching path
		for _, regexPath := range ti.URLPaths {
			if regexPath.MatchString(u.Path) {
				// Match found
				chanMatchFound <- struct{}{}
				return
			}
		}

		// No match found
		cancel()
	}()

	// Listen for completion of all goroutines before returning
	for {
		select {
		case <-chanMatchFound:
			// Match found
			fieldsMatched++
			if fieldsToCheck == fieldsMatched {
				// All fields have been checked without a match not being found;
				// thus, matches were found for all fields.
				return true
			}
		case <-ctx.Done():
			// No match found in any one single data point for this ruleset, which means that this entire rule set
			// does not match (all or nothing).
			return false
		}
	}
}

// ToTargetFilter converts the target/ignore list into a target filter object and returns it.
func (ti *TargetIgnore) ToTargetFilter() *TargetFilter {
	var wg sync.WaitGroup

	// Hosts
	hosts := make([]string, len(ti.Hosts))
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for domain := range ti.Hosts {
			hosts[i] = domain
			i++
		}
	}()

	// URL Paths
	paths := make([]string, len(ti.URLPaths))
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for path := range ti.URLPaths {
			paths[i] = path
			i++
		}
	}()

	// Response codes
	respCodes := make([]string, len(ti.RespCodes))
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for respCode := range ti.RespCodes {
			respCodes[i] = respCode
			i++
		}
	}()

	// URL schemes
	urlSchemes := make([]string, len(ti.URLSchemes))
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for urlScheme := range ti.URLSchemes {
			urlSchemes[i] = urlScheme
			i++
		}
	}()

	// HTTP request methods
	reqMethods := make([]string, len(ti.ReqMethods))
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for reqMethod := range ti.ReqMethods {
			reqMethods[i] = reqMethod
			i++
		}
	}()

	// HTTP parameter key:value pairs
	paramKeyValues := make(map[string][]string)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for key, values := range ti.ParamKeyValues {
			valuesSlice := make([]string, len(values.Values))
			i := 0
			for value := range values.Values {
				valuesSlice[i] = value
				i++
			}
			paramKeyValues[key] = valuesSlice
		}
	}()

	// HTTP request header key:value pairs
	headerKeyValuesRequest := make(map[string][]string)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for key, values := range ti.HeaderKeyValuesReq {
			valuesSlice := make([]string, len(values.Values))
			i := 0
			for value := range values.Values {
				valuesSlice[i] = value
				i++
			}
			headerKeyValuesRequest[key] = valuesSlice
		}
	}()

	// HTTP response header key:value pairs
	headerKeyValuesResponse := make(map[string][]string)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for key, values := range ti.HeaderKeyValuesResp {
			valuesSlice := make([]string, len(values.Values))
			i := 0
			for value := range values.Values {
				valuesSlice[i] = value
				i++
			}
			headerKeyValuesResponse[key] = valuesSlice
		}
	}()

	// Cookie key:value pairs
	cookieKeyValues := make(map[string][]string)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for key, values := range ti.CookieKeyValues {
			valuesSlice := make([]string, len(values.Values))
			i := 0
			for value := range values.Values {
				valuesSlice[i] = value
				i++
			}
			cookieKeyValues[key] = valuesSlice
		}
	}()

	wg.Wait()

	return &TargetFilter{
		Ignore:              ti.IsIgnore,
		Latest:              ti.Latest,
		Earliest:            ti.Earliest,
		Hosts:               hosts,
		URLPaths:            paths,
		RespCodes:           respCodes,
		URLSchemes:          urlSchemes,
		ReqMethods:          reqMethods,
		ParamKeyValues:      paramKeyValues,
		HeaderKeyValuesReq:  headerKeyValuesRequest,
		HeaderKeyValuesResp: headerKeyValuesResponse,
		CookieKeyValues:     cookieKeyValues,
	}
}

// regexStartString is used to match the start of the regular expressions we use in the target/ignore regex patterns.
var regexStartString = regexp.MustCompile("^\\(.+\\)\\^")

// regexToString converts the given target/ignore regular expression back to the string format used in the target filter.
func regexToString(regex *regexp.Regexp) string {
	r := regex.String()

	// Remove the flags from the beginning of the regex string (e.g. "im")
	r = regexStartString.ReplaceAllString(r, "")

	// Remove the trailing "$"
	r = strings.TrimSuffix(r, "$")

	// Replace all other special character
	r = strings.ReplaceAll(r, `.*`, `***`)
	r = strings.ReplaceAll(r, `\*`, `*`)
	r = strings.ReplaceAll(r, `\(`, `(`)
	r = strings.ReplaceAll(r, `\)`, `)`)
	r = strings.ReplaceAll(r, `\[`, `[`)
	r = strings.ReplaceAll(r, `\]`, `]`)
	r = strings.ReplaceAll(r, `\{`, `{`)
	r = strings.ReplaceAll(r, `\}`, `}`)
	r = strings.ReplaceAll(r, `\?`, `?`)
	r = strings.ReplaceAll(r, `\+`, `+`)
	r = strings.ReplaceAll(r, `\^`, `^`)
	r = strings.ReplaceAll(r, `\$`, `$`)
	r = strings.ReplaceAll(r, `\|`, `|`)
	r = strings.ReplaceAll(r, `\.`, `.`)
	r = strings.ReplaceAll(r, `\\`, `\`)

	return r
}

// TargetIgnoreSimple is a data structure for target or ignore settings, using only hosts to match against.
type TargetIgnoreSimple struct {
	// Set to true when the list is an ignore list
	IsIgnore bool

	// Hosts to target, mapping the target filter value to the regular expression value
	Hosts map[string]*regexp.Regexp
}

// MatchesHost returns true if the given URL hosts match the target/ignore list.
//
// The source and destination hosts are both checked if this is a target rule (i.e. first and second-degree matches).
// The destination is checked if this is an ignore rule (i.e. only direct matches).
//
// Each field is compared in a separate goroutine for speed and concurrency, and if
// any of the TargetIgnore fields do *not* match the given HttpReqResp structure,
// then this method returns false.
func (tis *TargetIgnoreSimple) MatchesHost(sourceHost, destinationHost string) (matches bool) {
	// Loop through all hosts, and return true if any match is found.
	for _, regexHost := range tis.Hosts {
		if regexHost.MatchString(destinationHost) {
			return true
		}

		// If ignore list, do not check the source host
		if tis.IsIgnore {
			continue
		}

		// If target list, check both the source and destination hosts
		if regexHost.MatchString(sourceHost) {
			return true
		}
	}

	return false
}

// ToTargetFilterSimple converts the target/ignore list into a simple target filter object and returns it.
func (tis *TargetIgnoreSimple) ToTargetFilterSimple() *TargetFilterSimple {
	tfs := &TargetFilterSimple{
		Ignore: tis.IsIgnore,
		Hosts:  make([]string, len(tis.Hosts)),
	}

	// Hosts
	i := 0
	for host := range tis.Hosts {
		tfs.Hosts[i] = host
		i++
	}

	return tfs
}
