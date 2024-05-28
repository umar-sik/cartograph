package webui

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/shared/users"
)

//go:embed templates/home/home.gohtml
var homeFS embed.FS

var homeTmpl *template.Template

func init() {
	var err error
	homeTmpl, err = template.ParseFS(homeFS, "templates/home/home.gohtml")
	if err != nil {
		panic(fmt.Errorf("unable to parse home template: %w", err))
	}
}

// home is an HTTP handler for the / endpoint.
//
// This handler is used to render the home page.
func (webUI *WebUI) home() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Reject if not GET request, and return valid methods with OPTIONS request
		if r.Method != http.MethodGet {
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "GET")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Get the user role from the request context's claims
		claims, jwtClaimsOk := r.Context().Value("claims").(*users.JWTClaims)
		if !jwtClaimsOk {
			log.WithField("claims", r.Context().Value("claims")).Error("unable to get claims from context")
			http.Error(w, "problem getting user role", http.StatusInternalServerError)
			return
		}

		// Convert the roles to a string slice
		roles := make([]string, len(claims.Roles))
		for i, role := range claims.Roles {
			roles[i] = users.ConvertToRole(role).String()
		}

		// Render home page
		if err := homeTmpl.Execute(w, struct {
			UserRoles []string
		}{
			UserRoles: roles,
		}); err != nil {
			log.WithError(err).Error("unable to render home page")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		return
	}
}
