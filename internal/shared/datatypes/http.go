package datatypes

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HttpReqResp represents HTTP request and response data.
type HttpReqResp struct {
	Request      HttpRequest
	Response     HttpResponse
	ReferrerData ReferrerData
	IPData       IPData
}

// IsIncomplete returns true if the data structure has not been completed.
// It checks all fields that must contain values according to the HTTP specs.
// The second return value is an error indicating what field was incomplete.
func (reqResp *HttpReqResp) IsIncomplete() (bool, error) {
	if reqResp.Request.Method == "" {
		return true, fmt.Errorf("request method is empty")
	}
	if reqResp.Request.Url.String() == "" {
		return true, fmt.Errorf("request URL is empty")
	}
	if reqResp.Request.Timestamp.IsZero() {
		return true, fmt.Errorf("request timestamp is empty")
	}
	if reqResp.Response.StatusCode == 0 {
		return true, fmt.Errorf("response status code is empty")
	}

	return false, nil
}

// DeepCopy returns a deep copy of the HttpReqResp struct, which can be safely modified without affecting the original.
// This does not copy the ReferrerData, which is only used for target matching.
func (reqResp *HttpReqResp) DeepCopy() HttpReqResp {
	copiedRequest := reqResp.Request.deepCopy()
	copiedResponse := reqResp.Response.deepCopy()
	copiedDestinationIP := make(net.IP, len(reqResp.IPData.Destination))
	copy(copiedDestinationIP, reqResp.IPData.Destination)

	return HttpReqResp{
		Request:  copiedRequest,
		Response: copiedResponse,
		IPData:   IPData{Destination: copiedDestinationIP},
	}
}

// HttpRequest represents the data from a single HTTP request.
type HttpRequest struct {
	Method    string
	Url       url.URL
	Header    http.Header
	Timestamp time.Time
	Cookies   []*http.Cookie

	// Include the body of the request, if the content-type is application/json
	BodyJson json.RawMessage

	// Include the body of the request, if the content-type is text/plain
	BodyText string
}

// deepCopy returns a deep copy of the HttpRequest struct, which can be safely modified without
// affecting the original.
func (req *HttpRequest) deepCopy() HttpRequest {
	copiedBodyJson := make([]byte, len(req.BodyJson))
	copy(copiedBodyJson, req.BodyJson)

	copiedHeader := make(http.Header)
	for k, v := range req.Header {
		copiedHeader[k] = v
	}

	copiedUrl := req.Url
	copiedCookies := make([]*http.Cookie, len(req.Cookies))
	for i, c := range req.Cookies {
		copiedCookies[i] = c
	}

	return HttpRequest{
		Method:    req.Method,
		Url:       copiedUrl,
		Header:    copiedHeader,
		Timestamp: req.Timestamp,
		Cookies:   copiedCookies,
		BodyJson:  copiedBodyJson,
	}
}

// HttpResponse represents the data from a single HTTP response.
type HttpResponse struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie

	// Include the body of the response, only if content-type is application/json
	BodyJson json.RawMessage

	// Include the body of the response, only if content-type is text/plain
	BodyText string
}

// deepCopy returns a deep copy of the HttpResponse struct, which can be safely modified without
// affecting the original.
func (resp *HttpResponse) deepCopy() HttpResponse {
	copiedBodyJson := make([]byte, len(resp.BodyJson))
	copy(copiedBodyJson, resp.BodyJson)

	copiedHeader := make(http.Header)
	for k, v := range resp.Header {
		copiedHeader[k] = v
	}

	copiedCookies := make([]*http.Cookie, len(resp.Cookies))
	for i, c := range resp.Cookies {
		copiedCookies[i] = c
	}

	return HttpResponse{
		StatusCode: resp.StatusCode,
		Header:     copiedHeader,
		Cookies:    copiedCookies,
		BodyJson:   copiedBodyJson,
	}
}

// IPData represents the IP address of the destination server.
type IPData struct {
	Destination net.IP
}
