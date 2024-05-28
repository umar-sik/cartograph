package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TheHackerDev/cartograph/internal/apiHunter"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/analyzer"
	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/mapper"
	"github.com/TheHackerDev/cartograph/internal/proxy/injector"
	"github.com/TheHackerDev/cartograph/internal/proxy/logger"
	"github.com/TheHackerDev/cartograph/internal/shared/datatypes"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
)

// NewProxy returns a new, properly instantiated Proxy object.
func NewProxy(cfg *config.Config, pluginInjector *injector.Injector, pluginLogger *logger.Logger, pluginMapper *mapper.Mapper, pluginAnalyzer *analyzer.Analyzer, pluginAPIHunter *apiHunter.APIHunter) *Proxy {
	proxy := &Proxy{
		pluginInjector:  pluginInjector,
		pluginLogger:    pluginLogger,
		pluginMapper:    pluginMapper,
		pluginAnalyzer:  pluginAnalyzer,
		pluginAPIHunter: pluginAPIHunter,
	}

	// Initialize a custom HTTP client
	proxy.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // This will get us the most coverage possible of remote servers
				MinVersion:         tls.VersionTLS10,
				CipherSuites: []uint16{
					// Support older server cipher suites
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				},
			},
			MaxIdleConns:        1024,             // Large number, but not unlimited
			MaxIdleConnsPerHost: 100,              // default is 2, this leaves a lot of flexibility for the client
			MaxConnsPerHost:     0,                // TODO: Consider lowering this value to prevent a single client from consuming all of the proxy's connections
			IdleConnTimeout:     90 * time.Second, // Same as the default http client
			// TLSHandshakeTimeout:   10 * time.Second,
			// ExpectContinueTimeout: 10 * time.Second,
		},
		// Do not follow redirects, which will allow the client/browser to handle them.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: nil,

		// Safe and sane timeouts
		Timeout: 2 * time.Minute,
	}

	// Parse the master config for SOCKS5 proxy data
	socks5URL := cfg.Socks5ProxyString
	if socks5URL != "" {
		u, socks5ParseErr := url.Parse(socks5URL)
		if socks5ParseErr != nil {
			log.WithError(socks5ParseErr).Errorf("unable to parse SOCKS5 URL string into URL type")
		} else {
			// Set the proxy's http client transport to use the SOCKS5 proxy
			proxy.httpClient.Transport = &http.Transport{
				Proxy: http.ProxyURL(u),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // This will get us the most coverage possible of remote servers
					MinVersion:         tls.VersionTLS10,
					CipherSuites: []uint16{
						// Support older server cipher suites
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					},
				},
				MaxIdleConns:        1024,             // Large number, but not unlimited
				MaxIdleConnsPerHost: 100,              // default is 2, this leaves a lot of flexibility for the client
				MaxConnsPerHost:     0,                // TODO: Consider lowering this value to prevent a single client from consuming all of the proxy's connections
				IdleConnTimeout:     90 * time.Second, // Same as the default http client
				// TLSHandshakeTimeout:   10 * time.Second,
				// ExpectContinueTimeout: 10 * time.Second,
			}
		}
	}

	// Instantiate the certificate manager
	var newCAMgrErr error
	proxy.certificateManager, newCAMgrErr = internalHttp.NewCertificateManager()
	if newCAMgrErr != nil {
		log.WithError(newCAMgrErr).Fatal("unable to instantiate certificate manager")
		return nil
	}

	// Set up the TLS config for the TLS server, with dynamic certificate generation and permissive cipher suites,
	// to support as many clients as possible.
	proxy.tlsServerConfig = &tls.Config{
		InsecureSkipVerify: true, // This is useful in the case of proxies being used between the client and us.
		GetCertificate:     proxy.certificateManager.GetCertificateDynamic(),
		MinVersion:         tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			// Support older clients
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}

	proxy.tlsClientConfig = &tls.Config{
		InsecureSkipVerify: true, // This will get us the most coverage possible of remote servers
		MinVersion:         tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			// Support older server cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}

	return proxy
}

// Proxy stores the configuration data for the Proxy plugin, and runs a standalone proxy service through the
// Run method.
// A Proxy object should *always* be instantiated via the NewProxy function.
type Proxy struct {
	// pluginInjector stores the injector plugin's instance, including configuration data.
	pluginInjector *injector.Injector

	// pluginLogger stores the logger plugin's instance, including configuration data.
	pluginLogger *logger.Logger

	// pluginMapper stores the mapper plugin's instance, including configuration data.
	pluginMapper *mapper.Mapper

	// pluginAnalyzer stores the analyzer plugin's instance, including configuration data.
	pluginAnalyzer *analyzer.Analyzer

	// pluginAPIHunter stores the APIHunter plugin's instance, including configuration data.
	pluginAPIHunter *apiHunter.APIHunter

	// httpClient is used by the proxy's HTTP handler to forward traffic to remote servers.
	httpClient *http.Client

	// tlsServerConfig stores the TLS server configuration used by the HTTPS proxy handler.
	tlsServerConfig *tls.Config

	// tlsClientConfig stores the TLS client configuration used by the TLS websocket proxy handler.
	tlsClientConfig *tls.Config

	// certificateManager stores the certificate manager used to generate certificates in the proxy.
	certificateManager *internalHttp.CertificateManager
}

// Run starts the proxy.
// Any errors returned should be considered fatal.
func (proxy *Proxy) Run() error {
	// Start the forward proxy server
	proxyServer := &http.Server{
		Addr:    ":8080", // Default; this can always be port mapped differently to the host with Docker at runtime
		Handler: proxy.httpHandler(),

		// Sane and safe timeouts
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second, // Gives us time to send a request to the remote server and receive a response
		IdleTimeout:  40 * time.Second,
	}
	return proxyServer.ListenAndServe()
}

// httpHandler handles all forward proxy HTTP requests.
func (proxy *Proxy) httpHandler() http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		// Handle HTTP CONNECT requests with the HTTPS proxy
		if request.Method == http.MethodConnect {
			proxy.httpsHandler(responseWriter, request)
			return
		}

		// Reject if not an absolute URI, as described in RFC 2616 section 5
		if !request.URL.IsAbs() {
			log.Errorf("URI provided is not absolute: %s, rejecting with 502 Bad Gateway response", request.URL.String())
			http.Error(responseWriter, fmt.Sprintf("URI provided is not absolute: %s", request.URL.String()), http.StatusBadGateway)
			return
		}

		// Handle requests for the mapper-worker.js file, which could be at any path (based on the requesting web page).
		// Verify that the path ends with "mapper-worker.js" and that the "X-Cartograph" header is set to
		// "mapper-worker.js".
		if strings.HasSuffix(request.URL.Path, proxy.pluginMapper.GetMapperWorkerScriptName()) && proxy.pluginMapper.Enabled() {
			// Serve the mapper-worker.js file
			proxy.serveMapperWorker(responseWriter, request)
			return
		}

		// Handle requests for the mapper.js file, which could be at any path (based on the requesting web page).
		// Verify that the path ends with "mapper.js" and that the "X-Cartograph" header is set to "mapper.js".
		// TODO: check for header, once mapper injection method implemented: if strings.HasSuffix(request.URL.Path, "mapper.js") && request.Header.Get("X-Cartograph") == "mapper.js" {
		if strings.HasSuffix(request.URL.Path, proxy.pluginMapper.GetMapperScriptName()) && proxy.pluginMapper.Enabled() {
			// Serve the mapper.js file
			proxy.serveMapper(responseWriter, request)
			return
		}

		// Handle mapper data sent from the browser, via the mapper injection scripts.
		// The request will be a POST request, with the "X-Cartograph" header set to "mapper-data".
		// The request will contain a JSON object in the body that looks like the following:
		// { source: "https://example.com", destination: "https://example.com" }
		if request.Method == http.MethodPost && request.Header.Get("X-Cartograph") == "mapper-data" {
			// Handle the mapper data
			proxy.handleMapperData(responseWriter, request)
			return
		}

		// Handle websocket connections
		if websocket.IsWebSocketUpgrade(request) {
			// Change the protocol
			request.URL.Scheme = "ws"

			proxy.wsProxy(responseWriter, request)
			return
		}

		// Start logging the request and response data
		reqResp := datatypes.HttpReqResp{
			Request: datatypes.HttpRequest{
				Method:    request.Method,
				Url:       *request.URL,
				Header:    request.Header.Clone(),
				Timestamp: time.Now(),
				Cookies:   request.Cookies(),
			},
		}

		// Save the API data from the request
		if apiRequestDataSaveErr := proxy.pluginAPIHunter.AddAPIRequestData(&reqResp, request); apiRequestDataSaveErr != nil {
			log.WithError(apiRequestDataSaveErr).Error("unable to save API request data")
		}

		// Prepare the mapper plugin's request data
		referrerData := &datatypes.ReferrerData{
			Destination: *request.URL,
			Timestamp:   time.Now(),
		}
		referer := request.Header.Get("Referer")
		if referer == "" {
			referrerData.Referer = url.URL{}
		} else {
			u, urlParseErr := url.Parse(referer)
			if urlParseErr != nil {
				log.WithError(urlParseErr).Errorf("unable to parse Referer header %s", referer)
			} else {
				referrerData.Referer = *u
			}
		}

		// Forward the request to the remote server
		resp, forwardErr := proxy.forwardRequest(request)
		if forwardErr != nil {
			if isTimeout(forwardErr) {
				// Respond with a 504 Gateway Timeout error code; do not log (ignore timeout errors... for now?)
				http.Error(responseWriter, fmt.Sprintf("forwarding request to %s timed out", request.URL.String()), http.StatusGatewayTimeout)
			} else {
				log.WithError(forwardErr).Errorf("unable to forward request to %s", request.URL.String())
				http.Error(responseWriter, fmt.Sprintf("unable to forward request to %s", request.URL.String()), http.StatusBadGateway)
			}
			return
		}

		// Handle chunked transfer encoding on the response
		if resp.TransferEncoding != nil && len(resp.TransferEncoding) > 0 && resp.TransferEncoding[0] == "chunked" {
			// Remove the timeout for writing the response to the client, as chunked transfer encoding can take a long
			// time, and writing the response won't complete until the entire response body is streamed (i.e. read
			// from).
			rc := http.NewResponseController(responseWriter)
			if writeDeadlineErr := rc.SetWriteDeadline(time.Time{}); writeDeadlineErr != nil {
				log.WithError(writeDeadlineErr).Error("unable to remove write deadline for chunked response")
			}

			var chunkedHandlerErr error
			resp, chunkedHandlerErr = proxy.handleChunkedResponse(resp)
			if chunkedHandlerErr != nil {
				log.WithError(chunkedHandlerErr).Error("unable to handle chunked response")
				http.Error(responseWriter, "unable to handle chunked response from remote server", http.StatusBadGateway)
				return
			}
		}

		// Save the response data
		reqResp.Response = datatypes.HttpResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header.Clone(),
			Cookies:    resp.Cookies(),
		}

		// Save the API data from the response
		if apiResponseDataSaveErr := proxy.pluginAPIHunter.AddAPIResponseData(&reqResp, resp); apiResponseDataSaveErr != nil {
			log.WithError(apiResponseDataSaveErr).Error("unable to save API response data")
		}

		// Send the response data to the logger
		proxy.pluginLogger.LogHttpData(&reqResp)

		// Send the referer data to the mapper
		proxy.pluginMapper.LogReferredData(referrerData)

		// Send the request and response data to the analyzer
		proxy.pluginAnalyzer.LogCorpusData(&reqResp)

		// Inject js, if applicable
		if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			// Mapper script injection
			if mapperInjectErr := proxy.pluginMapper.InjectMapperScript(resp, referrerData); mapperInjectErr != nil {
				log.WithError(mapperInjectErr).Error("unable to inject mapper script into response")
				http.Error(responseWriter, "unable to manage response", http.StatusBadGateway)
				return
			}

			// Injector script injection
			if injectErr := proxy.pluginInjector.JsInResponseHead(resp, *referrerData); injectErr != nil {
				log.WithError(injectErr).Error("unable to inject JavaScript into response")
				http.Error(responseWriter, "unable to manage response", http.StatusBadGateway)
				return
			}
		}

		// Prepare the response to send back to the client
		// Headers
		for key, values := range resp.Header {
			responseWriter.Header().Set(key, values[0])
			if len(values) > 1 {
				for _, value := range values {
					responseWriter.Header().Add(key, value)
				}
			}
		}
		// Status code
		responseWriter.WriteHeader(resp.StatusCode)
		// Body - we read this only to check the length before sending back to the client.
		respBody, bodyCopy, readErr := internalHttp.ReadBody(resp.Body)
		resp.Body = bodyCopy
		if readErr != nil {
			log.WithError(readErr).Error("unable to read HTTP response body from remote server")
			http.Error(responseWriter, "unable to read the response body from the remote server", http.StatusBadGateway)
			return
		}

		// Send the response back to the client, if allowed for the received status code
		if len(respBody) > 0 && internalHttp.BodyAllowedForStatus(resp.StatusCode) {
			// Body allowed; attempt to write
			if _, writeErr := responseWriter.Write(respBody); writeErr != nil {
				if writeErr.Error() != "https: stream closed" {
					// Only error that is not caused by a client disconnecting in HTTP/2
					log.WithError(writeErr).Error("unable to write remote server response to the client")
				}
			}
		}
	}
}

// httpsHandler handles all forward proxy HTTPS (i.e. SSL/TLS) requests.
func (proxy *Proxy) httpsHandler(response http.ResponseWriter, request *http.Request) {
	// Hijack the connection to handle it at the TCP layer
	hijacker, hijackOk := response.(http.Hijacker)
	if !hijackOk {
		// The server does not support hijacking; considered a fatal error
		http.Error(response, "proxy server does not support hijacking of HTTP connections", http.StatusBadGateway)
		log.WithError(fmt.Errorf("proxy server does not support HTTP hijacking")).Fatal("fatal proxy error. Exiting.")
		return
	}
	clientConn, _, hijackErr := hijacker.Hijack()
	if hijackErr != nil {
		log.WithError(hijackErr).Error("unable to hijack proxy connection")
		http.Error(response, fmt.Sprintf("unable to hijack HTTPS connection: %s", hijackErr.Error()), http.StatusBadGateway)
		return
	}

	// Ensure the client connection is closed when the function returns
	defer func() {
		if err := clientConn.Close(); err != nil {
			// Check if the connection was already closed.
			// This will happen if we have established a TLS connection with the client.
			// We keep this function here to ensure that the client connection is closed no matter what.
			// TODO: Change this to use "errors.As" to check for the specific error type and value.
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.WithError(err).Error("unable to close client connection from HTTPS handler")
			}
		}
	}()

	// Remove timeouts for these connections, as all CONNECT tunnels are expected to be long-lived.
	if deadlineErr := clientConn.SetDeadline(time.Time{}); deadlineErr != nil {
		log.WithError(deadlineErr).Error("unable to remove deadlines from TLS connection")
		return
	}

	// Continue the connection with a 200 Connection Established message
	if _, writeErr := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); writeErr != nil {
		if errors.Is(writeErr, syscall.ECONNRESET) {
			// connection reset by peer
			return
		}
		log.WithError(writeErr).Error("unable to write to client")
		return
	}

	// Start a TLS server to handle the connection
	tlsConn := tls.Server(clientConn, proxy.tlsServerConfig)

	// Ensure the TLS connection is closed, and log any unexpected errors
	defer func() {
		if tlsConnCloseErr := tlsConn.Close(); tlsConnCloseErr != nil {
			if errors.Is(tlsConnCloseErr, syscall.Errno(0x20)) {
				// Broken pipe errors are normally caused by browsers or other clients closing the response
				// immediately (ie not gracefully); they are usually safe to ignore.
				return
			}
			log.WithError(tlsConnCloseErr).Error("unable to close TLS connection to client before exiting HTTPS forward proxy handler")
			return
		}
	}()

	// Set a deadline now, which will be removed after the handshake completes, to ensure that we don't leave the
	// connection hanging in case of a handshake issue.
	if deadlineErr := tlsConn.SetDeadline(time.Now().Add(20 * time.Second)); deadlineErr != nil {
		log.WithError(deadlineErr).Error("unable to update TLS connection deadline before handshake")
		return
	}

	// Attempt a TLS handshake with the client
	if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
		if errors.Is(handshakeErr, io.EOF) {
			// EOF usually happens when a client (usually a browser) just opens a connection and immediately closes
			// it with EOF.
			return
		}
		if errors.Is(handshakeErr, syscall.ECONNRESET) {
			// connection reset by peer
			return
		}
		log.WithError(handshakeErr).Errorf("unexpected TLS handshake error received from client in TLS forward proxy for target host %s", tlsConn.ConnectionState().ServerName)
		return
	}

	// Remove timeouts for these connections, as all CONNECT tunnels are expected to be long-lived.
	if deadlineErr := tlsConn.SetDeadline(time.Time{}); deadlineErr != nil {
		log.WithError(deadlineErr).Error("unable to remove deadlines from TLS connection")
		return
	}

	// Create a buffered reader and writer for the client connection
	readClient := bufio.NewReader(tlsConn)
	// Create a buffered writer for the remote connection
	// writeClient := bufio.NewWriter(tlsConn)

	// Hold the context for client requests, as well as their cancellation functions, to ensure that they are cancelled
	// when the client connection is closed. Start with a background context, as we don't have a request yet.
	// clientCtx, clientCancelFunc := context.WithCancel(context.Background())

	// Ensure that the cancellation function is called when the function returns.
	// Calling it multiple times will do nothing.
	// defer clientCancelFunc()

	for {
		// // Ensure that the client context is cancelled from the last request
		// clientCancelFunc()

		// Read from the client
		tunnelReq, reqReadErr := http.ReadRequest(readClient)
		if reqReadErr != nil {
			if errors.Is(reqReadErr, io.EOF) {
				// EOF usually happens when a client (usually a browser) just opens a connection and immediately closes
				// it with EOF.
				return
			}
			if errors.Is(reqReadErr, syscall.ECONNRESET) {
				// connection reset by peer
				return
			}
			// Check for a tls alertUserCanceled (90) error, which is sent by the client when it closes the connection
			// without sending a proper TLS alert.
			// We have to read the error message to check for this, as the error type is not exported.
			if strings.Contains(reqReadErr.Error(), "user canceled") {
				// Client closed the connection without sending a proper TLS alert.
				return
			}
			log.WithError(reqReadErr).Errorf("unable to read request data from client for target server %s", tlsConn.ConnectionState().ServerName)
			return
		}

		// TODO: Handle CONNECT requests, which are used to establish another HTTPS forward proxy connection
		//  nested inside this one.

		// Copy the remote address over to the new request.
		// This is not copied over by the http.ReadRequest function.
		tunnelReq.RemoteAddr = request.RemoteAddr

		// Set the URL properly, as it is not filled in fully by http.ReadRequest
		tunnelReq.URL.Host = tunnelReq.Host
		tunnelReq.URL.Scheme = "https"

		// Handle requests for the mapper-worker.js file, which could be at any path (based on the requesting web page).
		// Verify that the path ends with "mapper-worker.js" and that the "X-Cartograph" header is set to
		// "mapper-worker.js".
		if strings.HasSuffix(tunnelReq.URL.Path, proxy.pluginMapper.GetMapperWorkerScriptName()) && proxy.pluginMapper.Enabled() {
			// Prepare a response to serve to the client, with the mapper-worker.js file contents (which is a byte
			// array)
			tunnelResp := http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type":        []string{"application/javascript"},
					"Content-Disposition": []string{fmt.Sprintf("attachment; filename=%q", proxy.pluginMapper.GetMapperWorkerScriptName())},
				},
				Body:          io.NopCloser(bytes.NewReader(proxy.pluginMapper.MapperWorkerScript)),
				Request:       tunnelReq,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				ContentLength: int64(len(proxy.pluginMapper.MapperWorkerScript)),
				Status:        "200 OK",
			}

			// Write the response to the client
			if writeErr := tunnelResp.Write(tlsConn); writeErr != nil {
				if errors.Is(writeErr, syscall.ECONNRESET) {
					// connection reset by peer
					return
				}
				log.WithError(writeErr).Error("unable to write mapper worker script to client")
				return
			}

			// Continue to the next request
			continue
		}

		// Handle requests for the mapper.js file, which could be at any path (based on the requesting web page).
		// Verify that the path ends with "mapper.js" and that the "X-Cartograph" header is set to "mapper.js".
		// TODO: check for header, once mapper injection method implemented: if strings.HasSuffix(tunnelReq.URL.Path, "mapper.js") && tunnelReq.Header.Get("X-Cartograph") == "mapper.js" {
		if strings.HasSuffix(tunnelReq.URL.Path, proxy.pluginMapper.GetMapperScriptName()) && proxy.pluginMapper.Enabled() {
			// Prepare a response to serve to the client, with the mapper.js file contents (which is a byte array)
			tunnelResp := http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type":        []string{"application/javascript"},
					"Content-Disposition": []string{fmt.Sprintf("attachment; filename=%q", proxy.pluginMapper.GetMapperScriptName())},
				},
				Body:          io.NopCloser(bytes.NewReader(proxy.pluginMapper.MapperScript)),
				Request:       tunnelReq,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				ContentLength: int64(len(proxy.pluginMapper.MapperScript)),
				Status:        "200 OK",
			}

			// Write the response to the client
			if writeErr := tunnelResp.Write(tlsConn); writeErr != nil {
				if errors.Is(writeErr, syscall.ECONNRESET) {
					// connection reset by peer
					return
				}
				log.WithError(writeErr).Error("unable to write mapper script to client")
				return
			}

			// Continue to the next request
			continue
		}

		// Handle mapper data sent from the browser, via the mapper injection scripts.
		// The request will be a POST request, with the "X-Cartograph" header set to "mapper-data".
		// The request will contain a JSON object in the body that looks like the following:
		// { source: "https://example.com", destination: "https://example.com" }
		if tunnelReq.Method == http.MethodPost && tunnelReq.Header.Get("X-Cartograph") == "mapper-data" {
			// Parse the request body into a MapperBrowserData object
			var browserData datatypes.MapperBrowserData
			if parseErr := json.NewDecoder(tunnelReq.Body).Decode(&browserData); parseErr != nil {
				log.WithError(parseErr).Error("unable to parse mapper browser data")
				return
			}

			// Parse the source URL
			sourceURL, sourceParseErr := url.Parse(browserData.Source)
			if sourceParseErr != nil {
				log.WithError(sourceParseErr).Error("unable to parse source URL from mapper data")
				return
			}

			// Add the browser data to the mapper
			for _, destination := range browserData.Destinations {
				// Parse the destination URL
				destinationURL, destinationParseErr := url.Parse(destination)
				if destinationParseErr != nil {
					log.WithError(destinationParseErr).Error("unable to parse destination URL from mapper data")
					continue
				}

				// Add the data to the mapper
				proxy.pluginMapper.LogReferredData(&datatypes.ReferrerData{
					Referer:     *sourceURL,
					Destination: *destinationURL,
					Timestamp:   time.Now(),
				})
			}

			// return a 200 OK response and close the connection
			tunnelResp := http.Response{
				StatusCode: http.StatusNoContent,
				Request:    tunnelReq,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Status:     "204 No Content",
			}
			if writeErr := tunnelResp.Write(tlsConn); writeErr != nil {
				if errors.Is(writeErr, syscall.ECONNRESET) {
					// connection reset by peer
					return
				}
				log.WithError(writeErr).Error("unable to write mapper data response to client")
				return
			}

			// Continue to the next request
			continue
		}

		// Check for websocket connection
		if websocket.IsWebSocketUpgrade(tunnelReq) {
			// Change the protocol
			tunnelReq.URL.Scheme = "wss"

			// Send to TLS websocket proxy
			proxy.wsProxyTLS(tlsConn, tunnelReq)
			return
		}

		// Start saving request and response data
		reqResp := datatypes.HttpReqResp{
			Request: datatypes.HttpRequest{
				Method:    tunnelReq.Method,
				Url:       *tunnelReq.URL,
				Header:    tunnelReq.Header.Clone(),
				Timestamp: time.Now(),
				Cookies:   tunnelReq.Cookies(),
			},
		}

		// Save the API data from the request
		if apiRequestDataSaveErr := proxy.pluginAPIHunter.AddAPIRequestData(&reqResp, tunnelReq); apiRequestDataSaveErr != nil {
			log.WithError(apiRequestDataSaveErr).Error("unable to save API request data")
		}

		// Prepare the mapper plugin's request data
		referrerData := &datatypes.ReferrerData{
			Destination: *tunnelReq.URL,
			Timestamp:   time.Now(),
		}
		referer := tunnelReq.Header.Get("Referer")
		if referer == "" {
			referrerData.Referer = url.URL{}
		} else {
			u, urlParseErr := url.Parse(referer)
			if urlParseErr != nil {
				log.WithError(urlParseErr).Errorf("unable to parse Referer header %s", referer)
			} else {
				referrerData.Referer = *u
			}
		}

		// Set the request timeout to be much higher than the default, as we don't want to timeout before writing to the client.
		// clientCtx, clientCancelFunc = context.WithDeadline(tunnelReq.Context(), time.Now().Add(365*24*time.Hour))
		// tunnelReq = tunnelReq.Clone(clientCtx)

		// Forward the request to the remote server
		tunnelResp, forwardErr := proxy.forwardRequest(tunnelReq)
		if forwardErr != nil {
			log.WithError(forwardErr).Error("unable to forward request to remote server")
			// Send a 502 Bad Gateway response to the client
			if _, writeErr := tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); writeErr != nil {
				// Check for broken pipe
				if errors.Is(writeErr, syscall.EPIPE) {
					// connection reset by peer
					return
				}
				log.WithError(writeErr).Error("unable to write closing response to client")
			}
			// TODO: Try changing "return" to "continue", and testing if there's a more graceful way to handle this.
			return
		}

		// TODO: Adjust the response timeout if the response is chunked, as it may take a long time to receive the full
		//  response. This is not easily possible right now, so the only solution I can think of is to increase the
		// 	timeout in the client to a very high value, and then cancel the request if it takes too long (essentially
		//  setting our own timeout manually with every request).

		// Check for chunked response data, which needs to be cached fully in memory before being sent to the client,
		// so that we can perform injection and save body data as needed.
		if tunnelResp.TransferEncoding != nil && len(tunnelResp.TransferEncoding) > 0 && tunnelResp.TransferEncoding[0] == "chunked" {
			var chunkHandlerErr error
			tunnelResp, chunkHandlerErr = proxy.handleChunkedResponse(tunnelResp)
			if chunkHandlerErr != nil {
				log.WithError(chunkHandlerErr).Error("unable to handle chunked response")
				// Send a 502 Bad Gateway response to the client
				if _, writeErr := tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); writeErr != nil {
					// Check for broken pipe
					if errors.Is(writeErr, syscall.EPIPE) {
						// connection reset by peer
						return
					}
					log.WithError(writeErr).Error("unable to write closing response to client")
				}
				return
			}
		}

		// Save the response data
		reqResp.Response = datatypes.HttpResponse{
			StatusCode: tunnelResp.StatusCode,
			Header:     tunnelResp.Header.Clone(),
			Cookies:    tunnelResp.Cookies(),
		}

		// Save the API data from the response
		if apiResponseDataSaveErr := proxy.pluginAPIHunter.AddAPIResponseData(&reqResp, tunnelResp); apiResponseDataSaveErr != nil {
			log.WithError(apiResponseDataSaveErr).Error("unable to save API response data")
		}

		// Save the request/response data
		proxy.pluginLogger.LogHttpData(&reqResp)

		// Save the mapper data
		proxy.pluginMapper.LogReferredData(referrerData)

		// Save the request/response data to the analyzer
		proxy.pluginAnalyzer.LogCorpusData(&reqResp)

		// Inject js into the response, if applicable
		if strings.Contains(tunnelResp.Header.Get("Content-Type"), "text/html") {
			// Mapper script injection
			if mapperInjectErr := proxy.pluginMapper.InjectMapperScript(tunnelResp, referrerData); mapperInjectErr != nil {
				log.WithError(mapperInjectErr).Error("unable to inject mapper script into response")
				if _, writeErr := tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); writeErr != nil {
					log.WithError(writeErr).Error("unable to write closing response to client")
				}
				return
			}

			// Injector script injection
			if injectErr := proxy.pluginInjector.JsInResponseHead(tunnelResp, *referrerData); injectErr != nil {
				log.WithError(injectErr).Error("unable to inject JavaScript into response")
				if _, writeErr := tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); writeErr != nil {
					log.WithError(writeErr).Error("unable to write closing response to client")
				}
				return
			}
		}

		// Write the response to the client
		if respWriteErr := tunnelResp.Write(tlsConn); respWriteErr != nil {
			// Check if it wraps an EPIPE error. If so, the client closed the connection, so we can ignore it.
			if errors.Is(respWriteErr, syscall.EPIPE) {
				return
			}
			// Format the response for logging
			var respStr string
			respStr += fmt.Sprintf("HTTP/1.1 %d %s\r\n", tunnelResp.StatusCode, tunnelResp.Status)
			for key, vals := range tunnelResp.Header {
				for _, val := range vals {
					respStr += fmt.Sprintf("%s: %s\r\n", key, val)
				}
			}
			respStr += "\r\n"
			// Cannot save the body, as it's been closed by the Write() call
			// respStr += fmt.Sprintf("%q", tunnelResp.Body)

			log.WithError(respWriteErr).WithField("response", respStr).Errorf("unable to write response data to client for target server %s", tlsConn.ConnectionState().ServerName)
			return
		}

		// If the header sent from the client is set to close, close the connection
		if tunnelReq.Close {
			return
		}
	}
}

// handleChunkedResponse handles a chunked response from the remote server. It returns a new, fully formed HTTP
// response, or an error.
// This function ensures that the original response body is closed, no matter what.
// If an error is returned, the new response will be nil.
func (proxy *Proxy) handleChunkedResponse(resp *http.Response) (*http.Response, error) {
	// Create a new buffer to hold the entire response
	var cache bytes.Buffer

	// Write the response to the buffer, which will automatically de-chunk the response
	if cacheWriteErr := resp.Write(&cache); cacheWriteErr != nil {
		return nil, fmt.Errorf("unable to write chunked response to cache: %w", cacheWriteErr)
	}

	// Read the cached response into a response object
	cachedResponse, cacheReadErr := http.ReadResponse(bufio.NewReader(&cache), resp.Request)
	if cacheReadErr != nil {
		return nil, fmt.Errorf("unable to read dechunked response from cache: %w", cacheReadErr)
	}

	return cachedResponse, nil
}

// isEOF returns true if the given reader's next byte is an EOF.
func isEOF(r *bufio.Reader) bool {
	_, peekErr := r.Peek(1)
	return errors.Is(peekErr, io.EOF)
}

// wsProxyUpgrader is used to upgrade websocket connections from clients.
var wsProxyUpgrader = websocket.Upgrader{
	HandshakeTimeout: 10 * time.Second,
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	// Error:             nil,
	CheckOrigin: func(request *http.Request) bool {
		// Allow all connections through, regardless of origin.
		// This leaves the origin check up to the remote server
		return true
	},
}

// wsData is used to store websocket data sent via the proxy.
type wsData struct {
	message []byte
	msgType int
}

// wsProxy proxies websocket data between the client and a remote server.
func (proxy *Proxy) wsProxy(response http.ResponseWriter, request *http.Request) {
	// Prepare the request and response data
	reqResp := datatypes.HttpReqResp{
		Request: datatypes.HttpRequest{
			Method:    request.Method,
			Url:       *request.URL,
			Header:    request.Header.Clone(),
			Timestamp: time.Now(),
			Cookies:   request.Cookies(),
		},
	}

	// Upgrade the connection to a websocket connection with the client.
	// This will remove the read and write deadlines on the request.
	clientConn, upgradeErr := wsProxyUpgrader.Upgrade(response, request, nil)
	if upgradeErr != nil {
		log.WithError(upgradeErr).Errorf("unable to upgrade websocket connection to %s", request.URL.String())
		return
	}

	// Ensure the client connection is closed
	defer func() {
		if clientCloseErr := clientConn.Close(); clientCloseErr != nil {
			log.WithError(clientCloseErr).Error("unable to close websocket connection to client")
		}
	}()

	// Create a dialer for the websocket connection to the remote server
	wsDialer := websocket.Dialer{
		// Proxy:             nil,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // allow the browser/client to handle insecure certificates
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
	}

	// Remove interfering headers from request (gorilla/websocket will return an error on duplicates,
	// rather than ignore them).
	for key := range request.Header {
		switch {
		case key == "Upgrade" ||
			key == "Connection" ||
			key == "Sec-Websocket-Key" ||
			key == "Sec-Websocket-Version" ||
			key == "Sec-Websocket-Extensions" ||
			(key == "Sec-Websocket-Protocol" && len(wsDialer.Subprotocols) > 0):
			request.Header.Del(key)
		}
	}

	// Start a websocket connection with the remote server
	serverConn, serverResp, dialErr := wsDialer.DialContext(context.Background(), request.URL.String(), request.Header)
	if dialErr != nil {
		// Log the error first, before attempting to send anything back to the client
		log.WithError(dialErr).Errorf("unable to establish a websocket connection with the remote server at %s", request.URL.String())

		// Send the error response back to the client
		if serverResp != nil {
			// Send the response to the logger;
			// in this case, it may be an authentication error or redirect, because there was a dial error.
			reqResp.Response = datatypes.HttpResponse{
				StatusCode: serverResp.StatusCode,
				Header:     serverResp.Header.Clone(),
				Cookies:    serverResp.Cookies(),
			}
			proxy.pluginLogger.LogHttpData(&reqResp)

			// Add all the header values from the server to the client response
			for key, values := range serverResp.Header {
				response.Header().Set(key, values[0])
				if len(values) > 1 {
					for _, value := range values {
						response.Header().Add(key, value)
					}
				}
			}

			// Set the status code from the server response
			response.WriteHeader(serverResp.StatusCode)

			// Copy and send the response body back to the client
			responseBody, bodyCopy, readErr := internalHttp.ReadBody(serverResp.Body)
			serverResp.Body = bodyCopy
			if readErr != nil {
				log.WithError(readErr).Error("unable to read response body from remote websocket server")
				http.Error(response, "unable to read response body from remote websocket server", http.StatusBadGateway)
				return
			}

			// Send the response body back to the client
			if len(responseBody) > 0 && internalHttp.BodyAllowedForStatus(serverResp.StatusCode) {
				_, writeErr := response.Write(responseBody)
				if writeErr != nil {
					log.WithError(writeErr).Error("unable to write response back to websocket client")
				}
			}
		}

		return
	}

	// Send the response to the logger
	reqResp.Response = datatypes.HttpResponse{
		StatusCode: serverResp.StatusCode,
		Header:     serverResp.Header.Clone(),
		Cookies:    serverResp.Cookies(),
	}
	proxy.pluginLogger.LogHttpData(&reqResp)

	// Ensure the server connection is closed
	defer func() {
		if serverCloseErr := serverConn.Close(); serverCloseErr != nil {
			log.WithError(serverCloseErr).Error("unable to close websocket connection to server")
		}
	}()

	// Prepare communication channels for concurrently proxying websocket connections between the client and
	// remote server
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	clientReceive := make(chan wsData)
	serverReceive := make(chan wsData)

	wg := new(sync.WaitGroup)

	// Receive client messages
	wg.Add(1)
	go func() {
		defer wg.Done()
		wsReceive(clientConn, clientDone, clientReceive)
	}()

	// Receive server messages
	wg.Add(1)
	go func() {
		defer wg.Done()
		wsReceive(serverConn, serverDone, serverReceive)
	}()

	// Send all messages to client and server
	wg.Add(1)
	go func() {
		defer wg.Done()
		wsClientServerSend(clientConn, serverConn, clientDone, serverDone, clientReceive, serverReceive)
	}()

	// Wait for all concurrent connections to be complete before returning
	wg.Wait()
}

// Regular expression to find port at the end of the URL
var urlHasPort = regexp.MustCompile(":\\d+$")

// wsProxyTLS proxies websocket data between the client and a remote server over TLS connections.
// In the future, we should look to implement more detailed inspection of the websocket data, similar to the wsProxy
// function now. We would basically have to handle the layer 7 websocket protocol data to get better context to what
// is being sent and received (look to gorilla/websockets implementation, which only uses raw TCP connections in their
// internal functions).
func (proxy *Proxy) wsProxyTLS(clientConn *tls.Conn, request *http.Request) {
	// If no port provided, assume 443 (default HTTPS port)
	var serverAddr string
	if urlHasPort.MatchString(request.URL.Host) {
		serverAddr = request.URL.Host
	} else {
		serverAddr = request.URL.Host + ":443"
	}

	// TODO: Log TLS websocket request and response data; this won't be possible until we add more fine-grained reading and writing of websocket data (like in the HTTP websocket proxy function).

	// Start a websocket connection with the remote server
	serverConn, serverConnErr := net.Dial("tcp", serverAddr)
	if serverConnErr != nil {
		log.WithError(serverConnErr).Error("unable to connect to remote host for websocket connection")
		return
	}

	// Convert connection to TLS connection
	serverConnTLS := tls.Client(serverConn, proxy.tlsClientConfig)

	// Ensure the TLS connection is closed, and log any unexpected errors
	defer func() {
		if serverConnCloseErr := serverConnTLS.Close(); serverConnCloseErr != nil {
			if errors.Is(serverConnErr, syscall.Errno(0x20)) {
				// Broken pipe errors are normally caused by browsers or other clients closing the response
				// immediately (ie not gracefully); they are usually safe to ignore.
				return
			}
			log.WithError(serverConnCloseErr).Error("unable to close TLS connection to remote server before exiting TLS websocket forward proxy handler")

			return
		}
	}()

	// Perform TLS handshake
	if handshakeErr := serverConnTLS.Handshake(); handshakeErr != nil {
		log.WithError(handshakeErr).Errorf("unexpected TLS handshake error received from server in TLS websocket forward proxy for target host %s", serverConnTLS.ConnectionState().ServerName)
		return
	}

	// Write original request data to remote server
	if writeErr := request.Write(serverConnTLS); writeErr != nil {
		log.WithError(writeErr).Error("unable to write TLS websocket request data to remote server")
		return
	}

	// Proxy websocket data between client and server
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Client -> server
		if _, clientCopyErr := io.Copy(serverConnTLS, clientConn); clientCopyErr != nil {
			if errors.Is(clientCopyErr, syscall.Errno(0x20)) {
				// broken pipe
				return
			}
			log.WithError(clientCopyErr).Error("unable to write websocket data to server")
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Server -> client
		if _, serverCopyErr := io.Copy(clientConn, serverConnTLS); serverCopyErr != nil {
			log.WithError(serverCopyErr).Error("unable to write websocket data to client")
		}
	}()
	wg.Wait()
}

// wsReceive sends data received from the websocket connection to the "received" channel, and indicates when the
// remote connection is closed by sending on the "done" channel.
// Any errors are logged directly by this function.
func wsReceive(wsConn *websocket.Conn, done chan<- bool, receive chan<- wsData) {
	for {
		// Get the latest message from the client
		msgType, msg, readErr := wsConn.ReadMessage()
		if readErr != nil {
			// Log the error message, if unexpected close error code is given
			if errLogMsg := fmtWsCloseErrMsg(readErr); errLogMsg != nil {
				log.WithError(errLogMsg).Error("unexpected close error code received on from websocket client")
			}

			// Indicate that the websocket connection is closed
			done <- true
			return
		}

		// Pass the received message
		receive <- wsData{
			message: msg,
			msgType: msgType,
		}
	}
}

// wsClientServerSend sends data between a client and server over a websocket connection based upon the data received
// on the "clientDone", "serverDone", "clientReceive", and "serverReceive" channels.
// Any errors are logged directly by this function.
func wsClientServerSend(clientConn, serverConn *websocket.Conn, clientDone, serverDone <-chan bool, clientReceive, serverReceive <-chan wsData) {
	for {
		select {
		case <-serverDone:
			// Server connection closed, send close message to client
			if writeErr := clientConn.WriteMessage(websocket.CloseMessage, []byte{}); writeErr != nil {
				// Log the error message, if unexpected close error code is given
				if errLogMsg := fmtWsCloseErrMsg(writeErr); errLogMsg != nil {
					log.WithError(errLogMsg).Error("unexpected close error code received from websocket client")
				}
			}

			return
		case <-clientDone:
			// Client closed connection, send close message to server
			if writeErr := serverConn.WriteMessage(websocket.CloseMessage, []byte{}); writeErr != nil {
				// Log the error message, if unexpected close error code is given
				if errLogMsg := fmtWsCloseErrMsg(writeErr); errLogMsg != nil {
					log.WithError(errLogMsg).Error("unexpected close error code received from websocket server")
				}
			}

			return
		case serverMsg := <-serverReceive:
			// Write server message to client
			if writeErr := clientConn.WriteMessage(serverMsg.msgType, serverMsg.message); writeErr != nil {
				// Log the error message, if unexpected close error code is given
				if errLogMsg := fmtWsCloseErrMsg(writeErr); errLogMsg != nil {
					log.WithError(errLogMsg).Error("unexpected close error code received from websocket client")
				}

				return
			}
		case clientMsg := <-clientReceive:
			// Write client message to server
			if writeErr := serverConn.WriteMessage(clientMsg.msgType, clientMsg.message); writeErr != nil {
				// Log the error message, if unexpected close error code is given
				if errLogMsg := fmtWsCloseErrMsg(writeErr); errLogMsg != nil {
					log.WithError(errLogMsg).Error("unexpected close error code received from websocket server")
				}

				return
			}
		}
	}
}

// fmtWsCloseErrMsg formats the given websocket close error to include the status code.
// Returns a nil error value if the close message is an expected close error.
func fmtWsCloseErrMsg(closeErr error) error {
	// Only log abnormal/unexpected close errors
	if websocket.IsUnexpectedCloseError(closeErr, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseNoStatusReceived) {
		var wsCloseErr *websocket.CloseError
		if errors.As(closeErr, &wsCloseErr) {
			return fmt.Errorf("websocket connection closed with unexpected status code %d: %w", wsCloseErr.Code, wsCloseErr)
		} else {
			return fmt.Errorf("websocket connection closed with unexpected status code: %w", wsCloseErr)
		}
	}

	return nil
}

// forwardRequests forwards the given request to a remote server, and returns the response.
func (proxy *Proxy) forwardRequest(request *http.Request) (*http.Response, error) {
	request.RequestURI = "" // this must be removed in client requests

	// Set the "X-Forwarded-For" header to ensure that the server knows this is a proxied request.
	// This will retain the original source IP of the request.
	// Only do this if request is NOT coming from an internal IP address.
	remoteHost, _, splitErr := net.SplitHostPort(request.RemoteAddr)
	if splitErr != nil {
		return nil, fmt.Errorf("unable to split remote address into host and port: %w", splitErr)
	}
	if !isPrivateIP(net.ParseIP(remoteHost)) {
		if proxies := request.Header.Get("X-Forwarded-For"); proxies != "" {
			// Other proxy addresses already set in header; add last hop to the end of the list
			request.Header.Set("X-Forwarded-For", fmt.Sprintf("%s %s", request.RemoteAddr, proxies))
		} else {
			request.Header.Set("X-Forwarded-For", request.RemoteAddr)
		}
	}

	// Drop the Referer header, to prevent disclosing sensitive information.
	// We've forced this header on every response, to better tie response data to request sources.
	// TODO: Do this only when the mapper plugin is enabled.
	request.Header.Del("Referer")

	// DEBUG: Add http tracing to request
	// trace := &httptrace.ClientTrace{
	// 	GetConn: func(hostPort string) {
	// 		log.WithField("hostPort", hostPort).Debugf("Get conn")
	// 	},
	// 	GotConn: func(info httptrace.GotConnInfo) {
	// 		log.WithField("GetConnInfo", fmt.Sprintf("%+v", info)).Debugf("Got conn")
	// 	},
	// 	PutIdleConn: func(err error) {
	// 		log.WithField("error", fmt.Sprintf("%+v", err)).Debugf("Put idle conn")
	// 	},
	// 	GotFirstResponseByte: func() {
	// 		log.Debugf("Got first response byte")
	// 	},
	// 	Got100Continue: func() {
	// 		log.Debugf("Got 100 Continue")
	// 	},
	// 	Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
	// 		log.WithFields(log.Fields{
	// 			"code":   code,
	// 			"header": fmt.Sprintf("%v+", header),
	// 		}).Debugf("Got 1xx response")
	// 		return nil
	// 	},
	// 	DNSStart: func(info httptrace.DNSStartInfo) {
	// 		log.WithField("info", fmt.Sprintf("%+v", info)).Debugf("DNS start")
	// 	},
	// 	DNSDone: func(info httptrace.DNSDoneInfo) {
	// 		log.WithField("info", fmt.Sprintf("%+v", info)).Debugf("DNS done")
	// 	},
	// 	ConnectStart: func(network, addr string) {
	// 		log.WithFields(log.Fields{
	// 			"network": network,
	// 			"addr":    addr,
	// 		}).Debugf("Connect start")
	// 	},
	// 	ConnectDone: func(network, addr string, err error) {
	// 		log.WithFields(log.Fields{
	// 			"network": network,
	// 			"addr":    addr,
	// 			"error":   fmt.Sprintf("%+v", err),
	// 		}).Debugf("Connect done")
	// 	},
	// 	TLSHandshakeStart: func() {
	// 		log.Debugf("TLS handshake start")
	// 	},
	// 	TLSHandshakeDone: func(state tls.ConnectionState, err error) {
	// 		log.WithFields(log.Fields{
	// 			"state": fmt.Sprintf("%+v", state),
	// 			"error": fmt.Sprintf("%+v", err),
	// 		}).Debugf("TLS handshake done")
	// 	},
	// 	WroteHeaderField: func(key string, value []string) {
	// 		log.WithFields(log.Fields{
	// 			"key":   key,
	// 			"value": fmt.Sprintf("%+v", value),
	// 		}).Debugf("Wrote header field")
	// 	},
	// 	WroteHeaders: func() {
	// 		log.Debugf("Wrote headers")
	// 	},
	// 	Wait100Continue: func() {
	// 		log.Debugf("Wait 100 Continue")
	// 	},
	// 	WroteRequest: func(info httptrace.WroteRequestInfo) {
	// 		log.WithField("info", fmt.Sprintf("%+v", info)).Debugf("Wrote request")
	// 	},
	// }
	// request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))

	// Send the request
	response, requestErr := proxy.httpClient.Do(request)
	if requestErr != nil {
		return nil, fmt.Errorf("unable to forward request: %w", requestErr)
	}

	// Force referrer data on all requests originating from this page
	// TODO: Only do this when the mapper plugin is enabled.
	response.Header.Set("Referrer-Policy", "unsafe-url")

	// Disable caching by the client
	// response.Header.Set("Cache-Control", "no-cache")
	// response.Header.Add("Cache-Control", "no-store")
	// response.Header.Add("Cache-Control", "must-revalidate")
	// response.Header.Set("Pragma", "no-cache")
	// response.Header.Set("Expires", "0")

	return response, nil
}

// serveMapperWorker serves the mapper-worker.js file to the client.
func (proxy *Proxy) serveMapperWorker(response http.ResponseWriter, request *http.Request) {
	// The mapper-worker.js file is a byte array, so we can just write it directly to the response,
	// ensuring that the response type is "blob" and the content type is "application/javascript".
	response.Header().Set("Content-Type", "application/javascript")
	response.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", proxy.pluginMapper.GetMapperWorkerScriptName()))
	response.Header().Set("Content-Length", strconv.Itoa(len(proxy.pluginMapper.MapperWorkerScript)))
	response.WriteHeader(http.StatusOK)
	if _, writeErr := response.Write(proxy.pluginMapper.MapperWorkerScript); writeErr != nil {
		log.WithError(writeErr).Errorf("unable to write mapper-worker.js to response")
	}
}

// serveMapper serves the mapper.js file to the client.
func (proxy *Proxy) serveMapper(response http.ResponseWriter, request *http.Request) {
	// The mapper.js file is a byte array, so we can just write it directly to the response,
	// ensuring that the response is appropriate for a javascript file.
	response.Header().Set("Content-Type", "application/javascript")
	response.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", proxy.pluginMapper.GetMapperScriptName()))
	response.Header().Set("Content-Length", strconv.Itoa(len(proxy.pluginMapper.MapperScript)))
	response.WriteHeader(http.StatusOK)
	if _, writeErr := response.Write(proxy.pluginMapper.MapperScript); writeErr != nil {
		log.WithError(writeErr).Errorf("unable to write mapper.js to response")
	}
}

// handleMapperData handles the data sent from the mapper.js file.
func (proxy *Proxy) handleMapperData(response http.ResponseWriter, request *http.Request) {
	// Get the request body
	body, bodyErr := io.ReadAll(request.Body)
	if bodyErr != nil {
		log.WithError(bodyErr).Errorf("unable to read request body")
		http.Error(response, "unable to read request body", http.StatusInternalServerError)
		return
	}

	// Unmarshal the request body
	var data datatypes.MapperBrowserData
	if unmarshalErr := json.Unmarshal(body, &data); unmarshalErr != nil {
		log.WithError(unmarshalErr).Errorf("unable to unmarshal request body")
		http.Error(response, "unable to unmarshal request body", http.StatusInternalServerError)
		return
	}

	// Parse the URLs
	sourceURL, sourceURLErr := url.Parse(data.Source)
	if sourceURLErr != nil {
		log.WithError(sourceURLErr).Errorf("unable to parse source URL")
		http.Error(response, "unable to parse source URL data", http.StatusInternalServerError)
		return
	}
	// Add the browser data to the mapper
	for _, destination := range data.Destinations {
		// Parse the destination URL
		destinationURL, destinationParseErr := url.Parse(destination)
		if destinationParseErr != nil {
			log.WithError(destinationParseErr).Error("unable to parse destination URL from mapper data")
			continue
		}

		// Add the data to the mapper
		proxy.pluginMapper.LogReferredData(&datatypes.ReferrerData{
			Referer:     *sourceURL,
			Destination: *destinationURL,
			Timestamp:   time.Now(),
		})
	}

	// Return a 204 response
	response.WriteHeader(http.StatusNoContent)
}

// isTimeout checks if err was caused by a timeout. To be specific, it is true if err is or was caused by a
// context.Canceled, context.DeadlineExceeded or an implementer of net.Error where Timeout() is true.
func isTimeout(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isPrivateIP reports whether ip is a private address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
// This also returns true if the address is a loopback address or a link-local
// unicast address.
func isPrivateIP(ip net.IP) bool {
	// Check for loopback or a link-local unicast addresses first, since they
	// are considered private for our purposes.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}
