package apiHunter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

// NewAPIHunter returns a new APIHunter object.
func NewAPIHunter() *APIHunter {
	return &APIHunter{
		// TODO: Add this to the config database table, and pull this value from there.
		enabled: true,
	}
}

// APIHunter is a module that is responsible for hunting for API endpoints.
// An APIHunter object should *always* be instantiated via the NewAPIHunter function.
type APIHunter struct {
	enabled bool
}

// Run starts the APIHunter module.
func (ah *APIHunter) Run() error {
	return nil
}

// AddAPIRequestData adds API request data to the HTTP request/response object, if present.
func (ah *APIHunter) AddAPIRequestData(reqResp *datatypes.HttpReqResp, request *http.Request) error {
	// Check if the APIHunter is enabled
	if !ah.enabled {
		return nil
	}

	// Look for text/plain request body
	for _, val := range request.Header.Values("Content-Type") {
		if strings.EqualFold(val, "text/plain") {
			// Save text/plain request body
			body, bodyCopy, readErr := internalHttp.ReadBody(request.Body)
			request.Body = bodyCopy
			if readErr != nil {
				return fmt.Errorf("unable to read body of HTTP request: %w", readErr)
			}
			reqResp.Request.BodyText = string(body)
			return nil
		}
	}

	// Look for JSON request body
	for _, val := range request.Header.Values("Content-Type") {
		if strings.EqualFold(val, "application/json") {
			// Save JSON request body
			body, bodyCopy, readErr := internalHttp.ReadBody(request.Body)
			request.Body = bodyCopy
			if readErr != nil {
				return fmt.Errorf("unable to read body of HTTP request: %w", readErr)
			}
			var bodyJson json.RawMessage = body
			reqResp.Request.BodyJson = bodyJson
			return nil
		}
	}

	return nil
}

// AddAPIResponseData adds API response data to the HTTP request/response object, if present.
func (ah *APIHunter) AddAPIResponseData(reqResp *datatypes.HttpReqResp, response *http.Response) error {
	// Check if the APIHunter is enabled
	if !ah.enabled {
		return nil
	}

	// Look for text/plain response body
	for _, val := range response.Header.Values("Content-Type") {
		if strings.EqualFold(val, "text/plain") {
			// Save text/plain request body
			var bodyText []byte
			body, bodyCopy, readErr := internalHttp.ReadBody(response.Body)
			response.Body = bodyCopy
			if readErr != nil {
				return fmt.Errorf("unable to read body of HTTP response: %w", readErr)
			}

			// Odd edge case, but it's happened
			if len(body) == 0 {
				return nil
			}

			// Decode and save body contents
			switch strings.ToLower(response.Header.Get("content-encoding")) {
			case "gzip":
				// Decode and save the data
				var decodeErr error
				bodyText, decodeErr = internalHttp.DecodeGzip(body)
				if decodeErr != nil {
					return fmt.Errorf("unable to decode gzip-encoded body of HTTP response: %w", decodeErr)
				}

				reqResp.Response.BodyText = string(bodyText)

				return nil
			case "br":
				// Decode and save the data
				var decodeErr error
				bodyText, decodeErr = internalHttp.DecodeBrotli(body)
				if decodeErr != nil {
					return fmt.Errorf("unable to decode brotli-encoded body of HTTP response: %w", decodeErr)
				}

				reqResp.Response.BodyText = string(bodyText)

				return nil
			case "deflate":
				// Decode and save the data
				var decodeErr error
				bodyText, decodeErr = internalHttp.DecodeDeflate(body)
				if decodeErr != nil {
					return fmt.Errorf("unable to decode deflate-encoded body of HTTP response: %w", decodeErr)
				}

				reqResp.Response.BodyText = string(bodyText)

				return nil
			default:
				if encodingType := response.Header.Get("content-encoding"); len(encodingType) > 0 {
					return fmt.Errorf("content-encoding type not supported in HTTP response: %s", encodingType)
				}

				// Body present, but not encoded
				reqResp.Response.BodyText = string(body)

				return nil
			}
		}
	}

	// Look for JSON response body
	for _, val := range response.Header.Values("Content-Type") {
		switch {
		// Check for different JSON types
		case strings.EqualFold(val, "application/json") || strings.EqualFold(val, "application/vnd.linkedin.normalized+json+2.1"):
			// Save JSON request body
			var bodyJson json.RawMessage
			body, bodyCopy, readErr := internalHttp.ReadBody(response.Body)
			response.Body = bodyCopy
			if readErr != nil {
				return fmt.Errorf("unable to read body of HTTP response: %w", readErr)
			}

			// Odd edge case, but it's happened
			if len(body) == 0 {
				return nil
			}

			// Decode and save body contents
			switch strings.ToLower(response.Header.Get("content-encoding")) {
			case "gzip":
				// Decode and save the data
				var decodeErr error
				bodyJson, decodeErr = internalHttp.DecodeGzip(body)
				if decodeErr != nil {
					return fmt.Errorf("unable to decode gzip-encoded body of HTTP response: %w", decodeErr)
				}

				reqResp.Response.BodyJson = bodyJson

				return nil
			case "br":
				// Decode and save the data
				var decodeErr error
				bodyJson, decodeErr = internalHttp.DecodeBrotli(body)
				if decodeErr != nil {
					return fmt.Errorf("unable to decode brotli-encoded body of HTTP response: %w", decodeErr)
				}

				reqResp.Response.BodyJson = bodyJson

				return nil
			case "deflate":
				// Decode and save the data
				var decodeErr error
				bodyJson, decodeErr = internalHttp.DecodeDeflate(body)
				if decodeErr != nil {
					return fmt.Errorf("unable to decode deflate-encoded body of HTTP response: %w", decodeErr)
				}

				reqResp.Response.BodyJson = bodyJson

				return nil
			default:
				if encodingType := response.Header.Get("content-encoding"); len(encodingType) > 0 {
					return fmt.Errorf("content-encoding type not supported in HTTP response: %s", encodingType)
				}

				// Body present, but not encoded
				reqResp.Response.BodyJson = body

				return nil
			}
		}
	}

	return nil
}
