package webui

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"

	log "github.com/sirupsen/logrus"
)

//go:embed templates/login/login.gohtml
var loginFS embed.FS

var loginTmpl *template.Template

func init() {
	var err error
	loginTmpl, err = template.ParseFS(loginFS, "templates/login/login.gohtml")
	if err != nil {
		panic(fmt.Errorf("unable to parse login template: %w", err))
	}
}

// login is an HTTP handler for the /login endpoint.
//
// This handler is used to log in to the web UI.
func (webUI *WebUI) login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Reject if not GET or POST request, and return valid methods with OPTIONS request
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "GET, POST")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check for the user JWT, and if valid, redirect to the home page
		userJWT, cookieErr := r.Cookie("user")
		if cookieErr == nil {
			if _, tokenErr := webUI.jwtManager.ValidateToken(userJWT.Value); tokenErr == nil {
				http.Redirect(w, r, "/home", http.StatusSeeOther)
				return
			}
		}

		// If GET request, render login page
		if r.Method == http.MethodGet {
			if err := loginTmpl.Execute(w, nil); err != nil {
				log.WithError(err).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		// If POST request, attempt to log in
		formParseErr := r.ParseForm()
		if formParseErr != nil {
			log.WithError(formParseErr).Error("unable to parse login form")

			// Redirect to login page, with error message
			if tmplExecuteErr := loginTmpl.Execute(w, &struct {
				Error string
			}{
				Error: "Invalid login.",
			}); tmplExecuteErr != nil {
				log.WithError(tmplExecuteErr).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		if username == "" || password == "" {
			if err := loginTmpl.Execute(w, &struct {
				Error string
			}{
				Error: "Username and password are required.",
			}); err != nil {
				log.WithError(err).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		// Fetch user's password hash and user roles from the database
		var passwordHash string
		var roles []int
		if hashQueryErr := webUI.dbConnPool.QueryRow(r.Context(), "SELECT password, roles FROM users WHERE username = $1", username).Scan(&passwordHash, &roles); hashQueryErr != nil {
			log.WithError(hashQueryErr).WithField("username", username).Error("unable to fetch user's password hash from database")

			// Redirect to login page, with error message
			if tmplExecuteErr := loginTmpl.Execute(w, &struct {
				Error string
			}{
				Error: "Invalid login.",
			}); tmplExecuteErr != nil {
				log.WithError(tmplExecuteErr).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		// Compare password hash with password
		verified, verifyErr := webUI.argon2ID.Verify(password, passwordHash)
		if verifyErr != nil {
			log.WithError(verifyErr).Error("unable to verify password hash")

			// Redirect to login page, with error message
			if tmplExecuteErr := loginTmpl.Execute(w, &struct {
				Error string
			}{
				Error: "Invalid login.",
			}); tmplExecuteErr != nil {
				log.WithError(tmplExecuteErr).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		// If password is incorrect, redirect to login page with error message
		if !verified {
			if err := loginTmpl.Execute(w, &struct {
				Error string
			}{
				Error: "Invalid login.",
			}); err != nil {
				log.WithError(err).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		// Generate a JWT for the user
		token, tokenErr := webUI.jwtManager.GenerateToken(username, roles)
		if tokenErr != nil {
			log.WithError(tokenErr).Error("unable to generate JWT")

			// Redirect to login page, with error message
			if tmplExecuteErr := loginTmpl.Execute(w, &struct {
				Error string
			}{
				Error: "Invalid login.",
			}); tmplExecuteErr != nil {
				log.WithError(tmplExecuteErr).Error("unable to render login page")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			return
		}

		// Set JWT as cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user",
			Value:    token,
			SameSite: http.SameSiteStrictMode,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
		})

		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
