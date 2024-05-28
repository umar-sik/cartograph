package injector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

// NewPayloadsJavaScriptAPIHandler returns a new instance of the JavaScript payloads API handler,
// using the provided injector object.
func NewPayloadsJavaScriptAPIHandler(config *Injector) *PayloadsJavaScriptAPIHandler {
	return &PayloadsJavaScriptAPIHandler{
		config:    config,
		uuidRegex: regexp.MustCompile(`(?i)(?P<payloads>/payloads)(?P<javascript>/javascript)/?(?P<uuid>[0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})?/?$`),
	}
}

// PayloadsJavaScriptAPIHandler performs the routing for the JavaScript payloads API.
//
// It conforms to the http.Handler interface, and should thus be used in a http.ServeMux instance as the handler for
// all JavaScript payloads API functions, starting at a single top-level URL path.
type PayloadsJavaScriptAPIHandler struct {
	// The plugin config.
	config *Injector

	// Regular expression to find a UUID, if provided in the path
	uuidRegex *regexp.Regexp
}

// ServeHTTP conforms to the http.Handler interface, allowing this method to handle HTTP requests
// for the Injector plugin's JavaScript payloads API.
// Requests are expected to be sent to a path ending in "/payloads/javascript/[uuid]", where the "[uuid]" is
// an optional value representing an individual JavaScript payload identifier.
func (h PayloadsJavaScriptAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the UUID from the request path, if one is provided
	targetUUID, pathErr := h.uuidInTargetsPath(r.URL.Path)
	if pathErr != nil {
		http.Error(w, fmt.Sprintf("invalid path provided: %q", r.URL.Path), http.StatusBadRequest)
		return
	}

	// Check for a valid request method, and send to the appropriate handler function
	switch r.Method {
	case "GET":
		h.getPayloads(targetUUID).ServeHTTP(w, r)
		return
	case "POST":
		h.addPayload().ServeHTTP(w, r)
		return
	case "DELETE":
		h.removePayload(targetUUID).ServeHTTP(w, r)
		return
	case "OPTIONS":
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "GET, POST, DELETE")
		return
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "invalid HTTP request method: "+r.Method, http.StatusMethodNotAllowed)
		return
	}
}

// uuidInTargetsPath returns the UUID, if one is found in the targets API path, or an empty string if it is not.
// An error is returned if the path does not match the proper structure of "/targets/[uuid]".
func (h PayloadsJavaScriptAPIHandler) uuidInTargetsPath(path string) (string, error) {
	// Check for correct path
	matches := h.uuidRegex.FindStringSubmatch(path)
	if matches == nil {
		return "", fmt.Errorf("invalid targets API path provided")
	}

	// Find UUID
	uuidIndex := h.uuidRegex.SubexpIndex("uuid")
	if uuidIndex == -1 {
		return "", fmt.Errorf("invalid regular expression provided: missing \"uuid\" subexpression")
	}

	return matches[uuidIndex], nil
}

// getPayloads is an HTTP handler function that returns either:
// - One JavaScript payload (URL), if the provided UUID is a valid ID.
// - All JavaScript payloads (URLs), if the provided UUID is an empty string.
func (h PayloadsJavaScriptAPIHandler) getPayloads(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id == "" {
			// No UUID value provided, get all JavaScript payload URLs
			payloads := h.config.getScriptURLs()

			// Marshal values to json to send in the response
			payloadsJSON, pJSONMarshalErr := json.Marshal(payloads)
			if pJSONMarshalErr != nil {
				http.Error(w, fmt.Sprintf("unable to convert JavaScript payloads to JSON: %s", pJSONMarshalErr.Error()), http.StatusInternalServerError)
				return
			}

			// Set the appropriate header for the content type in the response
			w.Header().Set("Content-Type", "application/json")

			// Write the response
			if _, writeErr := w.Write(payloadsJSON); writeErr != nil {
				http.Error(w, fmt.Sprintf("problem writing JSON response back: %s", writeErr.Error()), http.StatusInternalServerError)
				return
			}

			return
		}

		// UUID value provided, get single JavaScript payload URL
		payload := h.config.getScriptURL(id)
		if payload == "" {
			http.Error(w, "no JavaScript payload with provided id: "+id, http.StatusBadRequest)
			return
		}

		// Marshal value to JSON to send in the response
		pResponse := javaScriptPayload{PayloadURL: payload}
		payloadJSON, pJSONMarshalErr := json.Marshal(pResponse)
		if pJSONMarshalErr != nil {
			http.Error(w, fmt.Sprintf("unable to convert JavaScript payload to JSON: %s", pJSONMarshalErr.Error()), http.StatusInternalServerError)
			return
		}

		// Set the appropriate header for the content type in the response
		w.Header().Set("Content-Type", "application/json")

		// Write the response
		if _, writeErr := w.Write(payloadJSON); writeErr != nil {
			http.Error(w, fmt.Sprintf("problem writing JSON response back: %s", writeErr.Error()), http.StatusInternalServerError)
			return
		}

		return
	}
}

// javaScriptPayload holds the structure used in requests to and responses from the JavaScript payload API,
// specifically when adding (POST) a new JavaScript payload and when responding with a specific payload URL (GET).
type javaScriptPayload struct {
	// PayloadURL holds the JavaScript payload URL.
	PayloadURL string `json:"payload_url"`
}

// addPayload adds a JavaScript payload URL provided in the HTTP request to the plugin config.
func (h PayloadsJavaScriptAPIHandler) addPayload() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Ensure the content-type in the request is correct
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, fmt.Sprintf("Content-Type must be %q", "application/json"), http.StatusBadRequest)
			return
		}

		// Attempt to parse the JavaScript payload URL in the request
		reqBody, bodyCopy, bodyReadErr := internalHttp.ReadBody(r.Body)
		r.Body = bodyCopy
		if bodyReadErr != nil {
			http.Error(w, fmt.Sprintf("unable to read request body: %s", bodyReadErr.Error()), http.StatusInternalServerError)
			return
		}
		var payload javaScriptPayload
		if jsonUnmarshalErr := json.Unmarshal(reqBody, &payload); jsonUnmarshalErr != nil {
			http.Error(w, fmt.Sprintf("unable to parse JSON request body into JavaScript payload (URL): %s", jsonUnmarshalErr.Error()), http.StatusInternalServerError)
			return
		}

		// Save the new payload
		payloadID, addErr := h.config.addScriptURL(payload.PayloadURL)
		if addErr != nil {
			http.Error(w, fmt.Sprintf("unable to add JavaScript payload: %s", addErr.Error()), http.StatusInternalServerError)
			return
		}

		// Marshal the new payload ID into JSON
		responseMap := make(map[string]string, 1)
		responseMap["id"] = payloadID
		jResponse, responseMarshalErr := json.Marshal(responseMap)
		if responseMarshalErr != nil {
			http.Error(w, fmt.Sprintf("unable to convert response to JSON: %s", jResponse), http.StatusInternalServerError)
			return
		}

		// Set the appropriate status header
		w.WriteHeader(http.StatusCreated)

		// Set the appropriate header for the content type in the response
		w.Header().Set("Content-Type", "application/json")

		// Write the response
		if _, writeErr := w.Write(jResponse); writeErr != nil {
			http.Error(w, fmt.Sprintf("problem writing JSON response back: %s", writeErr.Error()), http.StatusInternalServerError)
			return
		}

		return
	}
}

// removePayload removes the given JavaScript payload ID from the plugin config.
func (h PayloadsJavaScriptAPIHandler) removePayload(id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for empty ID value
		if id == "" {
			http.Error(w, "no JavaScript payload ID provided in request URL path", http.StatusBadRequest)
			return
		}

		// Attempt to remove the given payload from the plugin injector
		if removeErr := h.config.removeScriptURL(id); removeErr != nil {
			http.Error(w, fmt.Sprintf("unable to remove JavaScript payload with ID %q: %s", id, removeErr.Error()), http.StatusInternalServerError)
			return
		}

		return
	}
}
