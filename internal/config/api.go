package config

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
)

// TargetsHandler is an HTTP handler for updating the targets.
func (c *Config) TargetsHandler(w http.ResponseWriter, r *http.Request) {
	// Check the request method
	switch r.Method {
	case "OPTIONS":
		w.WriteHeader(http.StatusNoContent)
		w.Header().Set("Allow", "GET, POST, DELETE")
		return
	case "GET":
		// Get all the targets
		targets := c.GetTargetsAndIgnoredAll()

		// Convert each target to a simple filter
		simpleTargets := make(map[string]*datatypes.TargetFilterSimple, len(targets))
		for i, target := range targets {
			simpleTargets[i] = target.ToTargetFilterSimple()
		}

		// Convert the targets to JSON
		targetsJSON, jsonErr := json.Marshal(simpleTargets)
		if jsonErr != nil {
			http.Error(w, fmt.Sprintf("unable to convert targets to JSON: %v", jsonErr), http.StatusInternalServerError)
			return
		}

		// Write the targets to the response
		w.Header().Set("Content-Type", "application/json")
		if _, writeErr := w.Write(targetsJSON); writeErr != nil {
			log.WithError(writeErr).Error("unable to write targets to response")
		}
	case "POST":
		// Read the target from the request
		target := &datatypes.TargetFilterSimple{}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(target)
		if decodeErr != nil {
			http.Error(w, fmt.Sprintf("unable to decode target from JSON: %v", decodeErr), http.StatusBadRequest)
			return
		}

		// Add the target to the configuration
		targetID, addErr := c.addTargetOrIgnored(target)
		if addErr != nil {
			http.Error(w, fmt.Sprintf("unable to add target to configuration: %v", addErr), http.StatusBadRequest)
			return
		}

		// Write the target ID to the response
		w.Header().Set("Content-Type", "text/plain")
		if _, writeErr := w.Write([]byte(targetID)); writeErr != nil {
			log.WithError(writeErr).Error("unable to write target ID to response")
		}
	case "DELETE":
		// Read the target ID from the request
		targetID := r.URL.Query().Get("id")
		if targetID == "" {
			http.Error(w, "missing target ID", http.StatusBadRequest)
			return
		}

		// Delete the target from the configuration
		deleteErr := c.deleteTargetOrIgnored(targetID)
		if deleteErr != nil {
			http.Error(w, fmt.Sprintf("unable to delete target from configuration: %v", deleteErr), http.StatusBadRequest)
			return
		}

		// Write the target ID to the response
		w.Header().Set("Content-Type", "text/plain")
		if _, writeErr := w.Write([]byte(targetID)); writeErr != nil {
			log.WithError(writeErr).Error("unable to write target ID to response")
		}
	default:
		http.Error(w, "invalid request method", http.StatusMethodNotAllowed)
	}
}
