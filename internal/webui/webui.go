package webui

import (
	"crypto/tls"
	"embed"
	_ "embed"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/TheHackerDev/cartograph/internal/config"
	"github.com/TheHackerDev/cartograph/internal/shared/database"
	internalHttp "github.com/TheHackerDev/cartograph/internal/shared/http"
	"github.com/TheHackerDev/cartograph/internal/shared/users"
)

//go:embed static/css/*.css static/css/*.map
var staticCSS embed.FS

//go:embed static/js/*.js static/js/*.map
var staticJS embed.FS

// NewWebUI returns a new web UI object using the given configuration.
//
// Any errors returned should be considered fatal.
func NewWebUI(cfg *config.Config) (*WebUI, error) {
	// Get a database connection pool
	dbConnPool, dbConnPoolErr := database.GetDbConnPool(cfg.DbConnString)
	if dbConnPoolErr != nil {
		return nil, dbConnPoolErr
	}

	// Get a certificate manager
	certificateManager, certificateManagerErr := internalHttp.NewCertificateManager()
	if certificateManagerErr != nil {
		return nil, certificateManagerErr
	}

	// Create a new web UI object
	webUI := &WebUI{
		dbConnPool:         dbConnPool,
		certificateManager: certificateManager,
		argon2ID:           users.NewArgon2ID(),
	}

	// Get a JWT manager
	jwtManager, jwtManagerErr := users.NewJWTManager()
	if jwtManagerErr != nil {
		return nil, jwtManagerErr
	}
	webUI.jwtManager = *jwtManager

	serveMux := http.NewServeMux()

	// Serve the "static" files
	serveMux.Handle("/static/css/", http.FileServer(http.FS(staticCSS)))
	serveMux.Handle("/static/js/", http.FileServer(http.FS(staticJS)))

	// Set up the web UI routes
	serveMux.HandleFunc("/review/bag-of-words", webUI.authenticated(webUI.reviewBagOfWords()))
	serveMux.HandleFunc("/login", webUI.login())
	serveMux.HandleFunc("/", webUI.authenticated(webUI.home()))

	// Create a new HTTPS server
	webUI.tlsServer = &http.Server{
		Addr:    ":443",
		Handler: serveMux,
		TLSConfig: &tls.Config{
			GetCertificate: webUI.certificateManager.GetCertificateDynamic(),
		},
	}

	// Create a new HTTP server
	webUI.httpServer = &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
		}),
	}

	return webUI, nil
}

// WebUI is the main object for the web UI plugin.
type WebUI struct {
	// dbConnPool is a connection pool to the database.
	dbConnPool *pgxpool.Pool

	// Manage the certificates for the HTTPS server
	certificateManager *internalHttp.CertificateManager

	// HTTPS server
	tlsServer *http.Server

	// HTTP server; redirects users to HTTPS
	httpServer *http.Server

	// argon2ID is an Argon2ID hasher, used for hashing and verifying passwords.
	argon2ID users.Argon2ID

	// jwtManager is a JWT manager, used for creating and verifying JWTs.
	jwtManager users.JWTManager
}

// Run starts the web UI server
func (webUI *WebUI) Run() error {
	// Error channel
	errChan := make(chan error)

	// Start the HTTP server
	go func() {
		errChan <- webUI.httpServer.ListenAndServe()
	}()

	// Start the HTTPS server
	go func() {
		errChan <- webUI.tlsServer.ListenAndServeTLS("", "")
	}()

	// Wait for an error
	return <-errChan
}
