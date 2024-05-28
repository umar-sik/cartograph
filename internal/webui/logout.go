package webui

import (
	"net/http"
)

// logout is an HTTP handler for the /logout endpoint.
//
// This handler is used to log out of the web UI.
func (webUI *WebUI) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Reject if not GET request, and return valid methods with OPTIONS request
		if r.Method != http.MethodGet {
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "GET")
				w.WriteHeader(http.StatusOK)
			}
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Delete the user JWT cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		// Redirect to the login page
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}
