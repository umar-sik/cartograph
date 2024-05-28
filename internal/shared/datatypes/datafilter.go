package datatypes

// DataFilter is a filter object for data API requests.
type DataFilter struct {
	Accept TargetFilterSimple `json:"accept"`
	Ignore TargetFilterSimple `json:"ignore"`
	Return TargetFilterSimple `json:"return"`
}

// ReturnFilter determines what data to return, when used with the data API.
type ReturnFilter struct {
	URLSchemes bool `json:"url_schemes"`
	Hosts      bool `json:"hosts"`
	Paths      bool `json:"paths"`

	RequestTypes  bool `json:"request_types"`
	ResponseCodes bool `json:"response_codes"`

	Parameters      bool `json:"parameters"`
	RequestHeaders  bool `json:"request_headers"`
	ResponseHeaders bool `json:"response_headers"`

	DateFound bool `json:"date_found"`
	LastSeen  bool `json:"last_seen"`
}
