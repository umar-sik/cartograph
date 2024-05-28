package http

import (
	"bytes"
	"io"
	"net/http"
)

// ReadBody safely reads the HTTP request or response body, returning a byte slice of the body contents, a copy of the
// body (to add back into the body), and an error, if any.
// This function closes the original body ReadCloser once it is read.
// No matter what, the copy output value is always valid. The original response body should always be overridden
// with this value.
func ReadBody(body io.ReadCloser) (contents []byte, copy io.ReadCloser, err error) {
	// TODO: Check for nil body before using this function.
	if body == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, http.NoBody, nil
	}
	if body == nil {
		return nil, nil, nil
	}
	var buf bytes.Buffer // TODO: Look at using an http.MaxBytesReader here instead, to control the size of the body.
	// Warning: if the body is too large, ReadFrom will panic with ErrTooLarge
	if _, err = buf.ReadFrom(body); err != nil {
		return nil, body, err
	}
	// TODO: This should be integrated in-line, so we can defer closing the original body within the same function.
	// if err = body.Close(); err != nil {
	// 	return nil, body, err
	// }
	return buf.Bytes(), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// BodyAllowedForStatus reports whether a given response status code permits a body.
// See RFC 7230, section 3.3.
// Note: This is used by http2/server.go automatically, so we will check for it ourselves first, in order to prevent
// invalid 500 return status codes to the client.
func BodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}
