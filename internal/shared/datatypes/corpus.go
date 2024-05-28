package datatypes

import (
	"regexp"
	"strings"
	"unicode"
)

// CorpusData is a struct that holds the data that will be used to create a corpus.
type CorpusData struct {
	// Select header keys that can be used to help identify and group requests into communities.
	HeaderKeys []string

	// Select parameter keys that can be used to help identify and group requests into communities.
	ParameterKeys []string

	// Select cookie keys that can be used to help identify and group request and response pairs into communities.
	CookieKeys []string

	// The parts of the URL path.
	URLPathParts []string

	// The value of the "Server" header.
	ServerValue string

	// The file extension of the URL path.
	// FileExtension string
}

// CorpusDataFromReqResp creates a CorpusData object from a HttpReqResp object.
func CorpusDataFromReqResp(reqResp *HttpReqResp) *CorpusData {
	corpusData := &CorpusData{}

	corpusData.HeaderKeys = make([]string, 0)
	corpusData.ParameterKeys = make([]string, 0)
	corpusData.URLPathParts = make([]string, 0)
	corpusData.CookieKeys = make([]string, 0)

	// Copy over the server value
	corpusData.ServerValue = strings.ToLower(reqResp.Response.Header.Get("Server"))

	// Copy over the cookie keys
	for _, cookie := range reqResp.Request.Cookies {
		corpusData.CookieKeys = append(corpusData.CookieKeys, strings.ToLower(cookie.Name))
	}

	// Remove unwanted request headers
	reqResp.Request.Header.Del("Cache-Control")
	reqResp.Request.Header.Del("Connection")
	reqResp.Request.Header.Del("Date")
	reqResp.Request.Header.Del("Pragma")
	reqResp.Request.Header.Del("Range")
	reqResp.Request.Header.Del("Host")
	reqResp.Request.Header.Del("User-Agent")
	reqResp.Request.Header.Del("Accept")
	reqResp.Request.Header.Del("Accept-Language")
	reqResp.Request.Header.Del("Accept-Encoding")
	reqResp.Request.Header.Del("Referer")
	reqResp.Request.Header.Del("If-Modified-Since")
	reqResp.Request.Header.Del("If-None-Match")
	reqResp.Request.Header.Del("Origin")
	reqResp.Request.Header.Del("dnt")
	reqResp.Request.Header.Del("Cookie")
	reqResp.Request.Header.Del("Cookie2")

	// Remove unwanted response headers
	reqResp.Response.Header.Del("Age")
	reqResp.Response.Header.Del("Cache-Control")
	reqResp.Response.Header.Del("Connection")
	reqResp.Response.Header.Del("Content-Length")
	reqResp.Response.Header.Del("Date")
	reqResp.Response.Header.Del("ETag")
	reqResp.Response.Header.Del("Expires")
	reqResp.Response.Header.Del("Last-Modified")
	reqResp.Response.Header.Del("Pragma")
	reqResp.Response.Header.Del("Transfer-Encoding")
	reqResp.Response.Header.Del("Vary")
	reqResp.Response.Header.Del("X-Content-Type-Options")
	reqResp.Response.Header.Del("X-XSS-Protection")
	reqResp.Response.Header.Del("Server")
	reqResp.Response.Header.Del("Content-Type")
	reqResp.Response.Header.Del("Content-Range")
	reqResp.Response.Header.Del("Last-Modified")
	reqResp.Response.Header.Del("Set-Cookie")
	reqResp.Response.Header.Del("Access-Control-Allow-Origin")
	reqResp.Response.Header.Del("Retry-After")

	// Copy over the request header keys, converted to lowercase
	for k := range reqResp.Request.Header {
		corpusData.HeaderKeys = append(corpusData.HeaderKeys, strings.ToLower(k))
	}

	// Copy over the response header keys, converted to lowercase
	for k := range reqResp.Response.Header {
		corpusData.HeaderKeys = append(corpusData.HeaderKeys, strings.ToLower(k))
	}

	// Copy over the parameter keys, converted to lowercase
	for k := range reqResp.Request.Url.Query() {
		// Remove any that may incidentally contain the full query string, which is known if they contain a "=" or a "?".
		if strings.Contains(k, "?") || strings.Contains(k, "=") {
			continue
		}

		corpusData.ParameterKeys = append(corpusData.ParameterKeys, strings.ToLower(k))
	}

	// Copy over the path parts
	// Split the path string into multiple strings
	split := splitPathString(reqResp.Request.Url.Path)

	// Add the split strings to the path parts
	for _, s := range split {
		corpusData.URLPathParts = append(corpusData.URLPathParts, s)
	}

	// Copy over the file extension, if one is present
	// if len(reqResp.Request.Url.Path) > 0 {
	//	// Get the last part of the path
	//	lastPart := reqResp.Request.Url.Path
	//	if strings.Contains(lastPart, "/") {
	//		lastPart = lastPart[strings.LastIndex(lastPart, "/")+1:]
	//	}
	//
	//	// Get the file extension
	//	if strings.Contains(lastPart, ".") {
	//		corpusData.FileExtension = lastPart[strings.LastIndex(lastPart, ".")+1:]
	//	}
	// }

	return corpusData
}

// splitParameterString splits a parameter string into a slice of strings.
// For example, "foo-bar" would be split into ["foo", "bar"].
// We split strings on dashes and underscores, and ignore strings that are too long (> 50 characters)
// or contain any numbers.
func splitParameterString(input string) []string {
	// Split on dash or underscore
	re := regexp.MustCompile(`[-_]`)
	split := re.Split(input, -1)

	// Remove any strings that are too long or contain numbers or special characters
	output := make([]string, 0)
	for _, s := range split {
		// Ignore strings that are too long (over 50 characters)
		if len(s) > 50 {
			continue
		}

		// Ignore strings that contain anything except for letters
		lettersOnly := true
		for _, c := range s {
			if !unicode.IsLetter(c) {
				lettersOnly = false
				break
			}
		}

		if !lettersOnly {
			continue
		}

		// Ignore empty strings
		if s == "" {
			continue
		}

		// Convert to lowercase before adding to the output
		output = append(output, strings.ToLower(s))
	}

	return output
}

// splitPathString splits a path string into a slice of strings.
// For example, "/foo/bar" would be split into ["foo", "bar"].
// We split strings on dashes and underscores, and ignore strings that are too long (> 50 characters)
// or contain any numbers.
func splitPathString(input string) []string {
	// Split on dash, underscore, or path separator (/)
	re := regexp.MustCompile(`[-_/]`)
	split := re.Split(input, -1)

	// Remove any strings that are too long or contain numbers
	output := make([]string, 0)
	for _, s := range split {
		// Ignore empty strings
		if s == "" {
			continue
		}

		// Ignore strings that are too long (over 50 characters)
		if len(s) > 50 {
			continue
		}

		// Ignore strings that contain numbers or other special characters
		lettersOrDotOnly := true
		for _, c := range s {
			if !unicode.IsLetter(c) && c != '.' {
				lettersOrDotOnly = false
				break
			}
		}

		if !lettersOrDotOnly {
			continue
		}

		// If the path contains a file extension, split the extension off
		if strings.Contains(s, ".") {
			s = strings.Split(s, ".")[0]
		}

		output = append(output, s)
	}

	return output
}

// FlaggedCorpusData is a struct that contains all flagged corpus data, used to identify interesting traffic.
type FlaggedCorpusData struct {
	// HeaderKeys is a slice of header keys in the request and response, converted to lowercase.
	HeaderKeys []string

	// ParameterKeys is a slice of parameter keys in the request, converted to lowercase.
	ParameterKeys []string

	// CookieKeys is a slice of cookie keys, converted to lowercase.
	CookieKeys []string

	// ServerHeaderValues is a slice of values in the Server header, converted to lowercase.
	ServerHeaderValues []string
}

// GetFlaggedCorpusData returns a FlaggedCorpusData struct containing all flagged corpus data.
// func GetFlaggedCorpusData(dbConn *pgx.Conn) (*FlaggedCorpusData, error) {
// 	// Get all flagged corpus data
// 	var flaggedCorpusData FlaggedCorpusData
// 	err := dbConn.QueryRow(context.Background(), `
// 		SELECT
// 			header_keys,
// 			parameter_keys,
// 			cookie_keys,
// 			server_header_values
// 		FROM flagged_corpus_data
// 		WHERE id = 1
// 	`).Scan(
// 		&flaggedCorpusData.HeaderKeys,
// 		&flaggedCorpusData.ParameterKeys,
// 		&flaggedCorpusData.CookieKeys,
// 		&flaggedCorpusData.ServerHeaderValues,
// 	)
// 	if err != nil {
// 		log.Fatal().Err(err).Msg("Failed to get flagged corpus data")
// 	}
//
// 	return flaggedCorpusData
// }
