package webui

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"github.com/gofrs/uuid"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/shared/users"
)

// BagOfWordsType is an enum for the different types of bag-of-words.
type BagOfWordsType int

const (
	Parameters BagOfWordsType = iota
	Headers
	ServerValues
	CookieKeys
)

func (t BagOfWordsType) String() string {
	return [...]string{"URL Parameters", "HTTP Headers", "HTTP Server Header Values", "Cookie Keys"}[t]
}

func (t BagOfWordsType) tableName() string {
	return [...]string{"corpus_url_param_keys", "corpus_http_header_keys", "corpus_server_header_values", "corpus_cookie_keys"}[t]
}

// validateBagOfWordsType returns true if the given integer is a valid BagOfWordsType.
func validateBagOfWordsType(t int) bool {
	return t >= 0 && t <= 3
}

//go:embed templates/review/review-bag-of-words.gohtml
var reviewBagOfWordsFS embed.FS

var reviewBagOfWordsTmpl *template.Template

func init() {
	var err error
	reviewBagOfWordsTmpl, err = template.ParseFS(reviewBagOfWordsFS, "templates/review/review-bag-of-words.gohtml")
	if err != nil {
		panic(fmt.Errorf("unable to parse review-bag-of-words template: %w", err))
	}
}

// reviewBagOfWords is an HTTP handler for the /review/bag-of-words endpoint.
//
// This handler is used to review the bag-of-words for a given corpus.
func (webUI *WebUI) reviewBagOfWords() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Reject if not GET or POST request, and return valid methods with OPTIONS request
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "GET, POST")
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		// Ensure the user is authorized by checking the role in the user claims
		claims, jwtClaimsOk := r.Context().Value("claims").(*users.JWTClaims)
		if !jwtClaimsOk {
			log.WithField("claims", r.Context().Value("claims")).Error("unable to get claims from context")
			http.Error(w, "problem getting user role", http.StatusInternalServerError)
			return
		}
		authorized := false
		for _, role := range claims.Roles {
			if users.ConvertToRole(role) == users.RoleReviewBow {
				authorized = true
				break
			}
		}
		if !authorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Get the type of bag-of-words to review from the URL query
		bagOfWordsType := r.URL.Query().Get("type")
		if bagOfWordsType == "" {
			// Set to 0 by default
			bagOfWordsType = "0"
		}

		// Convert the bag-of-words type to an integer from a string
		bagOfWordsTypeInt, atoiErr := strconv.Atoi(bagOfWordsType)
		if atoiErr != nil {
			http.Error(w, "invalid bag-of-words type", http.StatusBadRequest)
			return
		}

		// Validate the bag-of-words type
		if !validateBagOfWordsType(bagOfWordsTypeInt) {
			http.Error(w, "invalid bag-of-words type", http.StatusBadRequest)
			return
		}

		// Convert the roles to a string slice
		roles := make([]string, len(claims.Roles))
		for i, role := range claims.Roles {
			roles[i] = users.ConvertToRole(role).String()
		}

		// Handle GET requests by rendering the full template
		if r.Method == http.MethodGet {
			webUI.returnFullBagOfWordsReview(w, r, BagOfWordsType(bagOfWordsTypeInt), roles)
			return
		}

		// Parse the keep and remove values from the POST form
		formParseErr := r.ParseForm()
		if formParseErr != nil {
			http.Error(w, "unable to parse form", http.StatusBadRequest)
			return
		}
		var keep []string
		var remove []string
		var flagged []string
		var unflagged []string
		keepVals := r.PostForm["keep"]
		removeVals := r.PostForm["remove"]
		flaggedVals := r.PostForm["flagged"]
		unflaggedVals := r.PostForm["unflagged"]
		for _, val := range keepVals {
			keep = append(keep, val)
		}
		for _, val := range removeVals {
			remove = append(remove, val)
		}
		for _, val := range flaggedVals {
			flagged = append(flagged, val)
		}
		for _, val := range unflaggedVals {
			unflagged = append(unflagged, val)
		}

		// Update the bag-of-words in the database
		updateErr := webUI.updateBagOfWords(r.Context(), BagOfWordsType(bagOfWordsTypeInt), keep, remove, flagged, unflagged)
		if updateErr != nil {
			log.WithError(updateErr).Error("unable to update bag-of-words")
			http.Error(w, "unable to update bag-of-words", http.StatusInternalServerError)
			return
		}

		// Return the next bag-of-words to review using the "bagOfWordsValues" block in the template
		webUI.returnNextBagOfWordsReview(w, r, BagOfWordsType(bagOfWordsTypeInt))
	}
}

// Word represents a word from a bag-of-words data set.
type Word struct {
	Name  string
	Count int
}

// returnFullBagOfWordsReview renders the full review-bag-of-words template.
func (webUI *WebUI) returnFullBagOfWordsReview(w http.ResponseWriter, r *http.Request, bagOfWordsType BagOfWordsType, userRoles []string) {
	// Get the unreviewed bag-of-words for the given type
	unreviewedBagOfWords, unreviewedBagOfWordsErr := webUI.getUnreviewedBagOfWords(r.Context(), bagOfWordsType)
	if unreviewedBagOfWordsErr != nil {
		http.Error(w, "unable to get unreviewed bag-of-words", http.StatusInternalServerError)
		return
	}

	// Render the template
	tmplErr := reviewBagOfWordsTmpl.Execute(w, struct {
		BagOfWordsType BagOfWordsType
		BagOfWords     map[string]Word
		UserRoles      []string
	}{
		BagOfWordsType: bagOfWordsType,
		BagOfWords:     unreviewedBagOfWords,
		UserRoles:      userRoles,
	})
	if tmplErr != nil {
		http.Error(w, "unable to render template", http.StatusInternalServerError)
		return
	}
}

// returnNextBagOfWordsReview renders the "bagOfWordsValues" block in the template with the next
// unreviewed bag-of-words.
func (webUI *WebUI) returnNextBagOfWordsReview(w http.ResponseWriter, r *http.Request, wordsType BagOfWordsType) {
	// Get the next unreviewed bag-of-words for the given type
	unreviewedBagOfWords, unreviewedBagOfWordsErr := webUI.getUnreviewedBagOfWords(r.Context(), wordsType)
	if unreviewedBagOfWordsErr != nil {
		http.Error(w, "unable to get unreviewed bag-of-words", http.StatusInternalServerError)
		return
	}

	// Render the "bagOfWordsValues" block in the template
	tmplErr := reviewBagOfWordsTmpl.ExecuteTemplate(w, "bagOfWordsValues", unreviewedBagOfWords)
	if tmplErr != nil {
		http.Error(w, "unable to render template", http.StatusInternalServerError)
		return
	}
}

// getUnreviewedBagOfWords returns a map of unreviewed bag-of-words for the given type.
// The map is keyed by the bag-of-words ID, and the value is a structure containing the name and count for the
// bag-of-words value.
// The map will contain at most 10 of the oldest unreviewed bag-of-words.
func (webUI *WebUI) getUnreviewedBagOfWords(ctx context.Context, bagOfWordsType BagOfWordsType) (map[string]Word, error) {
	sqlQuery := fmt.Sprintf("select id, name, count from %s where reviewed is false order by found limit 10;", bagOfWordsType.tableName())

	rows, queryErr := webUI.dbConnPool.Query(ctx, sqlQuery)
	if queryErr != nil {
		return nil, queryErr
	}
	defer rows.Close()

	bagOfWords := make(map[string]Word)
	for rows.Next() {
		var id uuid.UUID
		var name string
		var count int
		scanErr := rows.Scan(&id, &name, &count)
		if scanErr != nil {
			return nil, scanErr
		}
		bagOfWords[id.String()] = Word{
			Name:  name,
			Count: count,
		}
	}

	return bagOfWords, nil
}

// updateBagOfWords updates the bag-of-words values in the database.
// The keep and remove slices contain the IDs of the bag-of-words to keep and remove, respectively.
// All IDs are also marked as reviewed.
func (webUI *WebUI) updateBagOfWords(context context.Context, bagOfWordsType BagOfWordsType, keep, remove, flagged, unflagged []string) error {
	if len(keep) == 0 && len(remove) == 0 && len(flagged) == 0 && len(unflagged) == 0 {
		return nil
	}

	var keepSQL string
	if len(keep) > 0 {
		keepSQL = fmt.Sprintf("update %s set reviewed = true, keep = true where id = any($1);", bagOfWordsType.tableName())
	}

	var removeSQL string
	if len(remove) > 0 {
		removeSQL = fmt.Sprintf("update %s set reviewed = true, keep = false where id = any($1);", bagOfWordsType.tableName())
	}

	var flaggedSQL string
	if len(flagged) > 0 {
		flaggedSQL = fmt.Sprintf("update %s set reviewed = true, flagged = true where id = any($1);", bagOfWordsType.tableName())
	}

	var unflaggedSQL string
	if len(unflagged) > 0 {
		unflaggedSQL = fmt.Sprintf("update %s set reviewed = true, flagged = false where id = any($1);", bagOfWordsType.tableName())
	}

	tx, txErr := webUI.dbConnPool.Begin(context)
	if txErr != nil {
		return txErr
	}

	if len(keep) > 0 {
		// Convert the string array to UUIDs to use in the SQL query
		keepVals := make([]uuid.UUID, len(keep))
		for i, id := range keep {
			uuidVal, convErr := uuid.FromString(id)
			if convErr != nil {
				if rollbackErr := tx.Rollback(context); rollbackErr != nil {
					log.WithError(rollbackErr).Error("unable to rollback transaction")
				}
				return convErr
			}
			keepVals[i] = uuidVal
		}
		_, keepExecErr := tx.Exec(context, keepSQL, keepVals)
		if keepExecErr != nil {
			if rollbackErr := tx.Rollback(context); rollbackErr != nil {
				log.WithError(rollbackErr).Error("unable to rollback transaction")
			}
			return keepExecErr
		}
	}

	if len(remove) > 0 {
		// Convert the string array to UUIDs to use in the SQL query
		removeVals := make([]uuid.UUID, len(remove))
		for i, id := range remove {
			uuidVal, convErr := uuid.FromString(id)
			if convErr != nil {
				if rollbackErr := tx.Rollback(context); rollbackErr != nil {
					log.WithError(rollbackErr).Error("unable to rollback transaction")
				}
				return convErr
			}
			removeVals[i] = uuidVal
		}
		_, removeExecErr := tx.Exec(context, removeSQL, removeVals)
		if removeExecErr != nil {
			if rollbackErr := tx.Rollback(context); rollbackErr != nil {
				log.WithError(rollbackErr).Error("unable to rollback transaction")
			}
			return removeExecErr
		}
	}

	if len(flagged) > 0 {
		// Convert the string array to UUIDs to use in the SQL query
		flaggedVals := make([]uuid.UUID, len(flagged))
		for i, id := range flagged {
			uuidVal, convErr := uuid.FromString(id)
			if convErr != nil {
				if rollbackErr := tx.Rollback(context); rollbackErr != nil {
					log.WithError(rollbackErr).Error("unable to rollback transaction")
				}
				return convErr
			}
			flaggedVals[i] = uuidVal
		}
		_, flaggedExecErr := tx.Exec(context, flaggedSQL, flaggedVals)
		if flaggedExecErr != nil {
			if rollbackErr := tx.Rollback(context); rollbackErr != nil {
				log.WithError(rollbackErr).Error("unable to rollback transaction")
			}
			return flaggedExecErr
		}
	}

	if len(unflagged) > 0 {
		// Convert the string array to UUIDs to use in the SQL query
		unflaggedVals := make([]uuid.UUID, len(unflagged))
		for i, id := range unflagged {
			uuidVal, convErr := uuid.FromString(id)
			if convErr != nil {
				if rollbackErr := tx.Rollback(context); rollbackErr != nil {
					log.WithError(rollbackErr).Error("unable to rollback transaction")
				}
				return convErr
			}
			unflaggedVals[i] = uuidVal
		}
		_, unflaggedExecErr := tx.Exec(context, unflaggedSQL, unflaggedVals)
		if unflaggedExecErr != nil {
			if rollbackErr := tx.Rollback(context); rollbackErr != nil {
				log.WithError(rollbackErr).Error("unable to rollback transaction")
			}
			return unflaggedExecErr
		}
	}

	if commitErr := tx.Commit(context); commitErr != nil {
		return commitErr
	}

	return nil
}
