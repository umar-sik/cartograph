package logger

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

// DataAPIHandler is a http handler function that handles requests to the data API, using DataFilter objects.
func DataAPIHandler(logger *Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only allow POST requests (or OPTIONS)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			w.Header().Set("Allow", "POST")
			return
		} else if r.Method != http.MethodPost {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		// Attempt to parse the data filter object from the request
		reqBody, bodyCopy, bodyReadErr := internalHttp.ReadBody(r.Body)
		r.Body = bodyCopy
		if bodyReadErr != nil {
			http.Error(w, fmt.Sprintf("unable to read request body: %s", bodyReadErr.Error()), http.StatusInternalServerError)
			return
		}
		var df datatypes.DataFilter
		if jsonUnMarshalErr := json.Unmarshal(reqBody, &df); jsonUnMarshalErr != nil {
			http.Error(w, fmt.Sprintf("unable to parse JSON request body into data filter object: %s", jsonUnMarshalErr.Error()), http.StatusInternalServerError)
			return
		}

		// Get the data
		data, getErr := logger.getData(&df)
		if getErr != nil {
			http.Error(w, fmt.Sprintf("unable to get data for given data filter: %s", getErr.Error()), http.StatusInternalServerError)
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

		return
	}
}
