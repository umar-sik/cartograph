package datatypes

import (
	"net/url"
	"time"
)

// ReferrerData is a struct that holds the referer and destination URLs from a single HTTP request.
type ReferrerData struct {
	Referer     url.URL
	Destination url.URL
	Timestamp   time.Time
}

// MapperBrowserData holds mapper data sent from our browser scripts.
type MapperBrowserData struct {
	Source       string   `json:"source"`
	Destinations []string `json:"destinations"`
}
