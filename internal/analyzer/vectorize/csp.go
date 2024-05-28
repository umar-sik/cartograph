package vectorize

import (
	"crypto/rand"
	"math/big"
	"strings"

	log "github.com/sirupsen/logrus"
)

// csp.go contains the code to vectorize a CSP (Content Security Policy) header.

// CspHeader vectorizes CSP headers into a vector of features.
func CspHeader(cspHeaders []string) []float32 {
	features := parseCSPFeatures(cspHeaders)
	return features
}

const (
	cspDefaultSrcNone               = iota // Default-src directive with 'none' value
	cspDefaultSrcSelf                      // Default-src directive with 'self' value
	cspDefaultSrcUnsafeInline              // Default-src directive with 'unsafe-inline' value
	cspDefaultSrcUnsafeEval                // Default-src directive with 'unsafe-eval' value
	cspDefaultSrcStrictDynamic             // Default-src directive with 'strict-dynamic' value
	cspDefaultSrcNonce                     // Default-src directive with nonce value (e.g., 'nonce-xyz')
	cspDefaultSrcSHA                       // Default-src directive with SHA value (e.g., 'sha256-xyz')
	cspDefaultSrcData                      // Default-src directive with data URL (e.g., 'data:image/png;base64')
	cspDefaultSrcHttps                     // Default-src directive with https URL (e.g., 'https://example.com')
	cspDefaultSrcHttp                      // Default-src directive with http URL (e.g., 'http://example.com')
	cspDefaultSrcCustomURL                 // Default-src directive with custom URL (e.g., 'https://custom.example.com')
	cspScriptSrcUnsafeHashes               // Script-src directive with 'unsafe-hashes' value
	cspBaseUriNone                         // Base-uri directive with 'none' value
	cspBaseUriSelf                         // Base-uri directive with 'self' value
	cspBaseUriCustomURL                    // Base-uri directive with custom URL (e.g., 'https://custom.example.com')
	cspFormActionNone                      // Form-action directive with 'none' value
	cspFormActionSelf                      // Form-action directive with 'self' value
	cspFormActionCustomURL                 // Form-action directive with custom URL (e.g., 'https://custom.example.com')
	cspFrameAncestorsNone                  // Frame-ancestors directive with 'none' value
	cspFrameAncestorsSelf                  // Frame-ancestors directive with 'self' value
	cspFrameAncestorsCustomURL             // Frame-ancestors directive with custom URL (e.g., 'https://custom.example.com')
	cspPluginTypesMimeType                 // Plugin-types directive with mime type (e.g., 'application/pdf')
	cspSandbox                             // Presence of sandbox directive
	cspReportUriCustomURL                  // Report-uri directive with custom URL (e.g., 'https://report.example.com')
	cspReportToCustomGroup                 // Report-to directive with custom group (e.g., 'group1')
	cspOtherDirectivesWithCustomURL        // Other CSP directives with custom URL (e.g., 'https://other.example.com')
	cspNumFeatures                         // Total number of features (used for initializing arrays/slices)
)

// parseCSPFeatures parses CSP headers into a vector of features.
func parseCSPFeatures(cspHeaders []string) []float32 {
	features := make([]float32, cspNumFeatures)

	for _, cspHeader := range cspHeaders {
		parsedCSP := parseCSP(cspHeader)
		for directive, values := range parsedCSP {
			for _, value := range values {
				switch {
				case directive == "default-src" && value == "'none'":
					features[cspDefaultSrcNone] = 1
				case directive == "default-src" && value == "'self'":
					features[cspDefaultSrcSelf] = 1
				case directive == "default-src" && strings.HasPrefix(value, "'unsafe-inline'"):
					features[cspDefaultSrcUnsafeInline] = 1
				case directive == "default-src" && strings.HasPrefix(value, "'unsafe-eval'"):
					features[cspDefaultSrcUnsafeEval] = 1
				case directive == "default-src" && strings.HasPrefix(value, "'strict-dynamic'"):
					features[cspDefaultSrcStrictDynamic] = 1
				case directive == "default-src" && strings.HasPrefix(value, "nonce-"):
					features[cspDefaultSrcNonce] = 1
				case directive == "default-src" && strings.HasPrefix(value, "sha"):
					features[cspDefaultSrcSHA] = 1
				case directive == "default-src" && strings.HasPrefix(value, "data:"):
					features[cspDefaultSrcData] = 1
				case directive == "default-src" && strings.HasPrefix(value, "https:"):
					features[cspDefaultSrcHttps] = 1
				case directive == "default-src" && strings.HasPrefix(value, "http:"):
					features[cspDefaultSrcHttp] = 1
				case directive == "default-src":
					features[cspDefaultSrcCustomURL] = 1
				case directive == "script-src" && strings.HasPrefix(value, "'unsafe-hashes'"):
					features[cspScriptSrcUnsafeHashes] = 1
				case directive == "base-uri" && value == "'none'":
					features[cspBaseUriNone] = 1
				case directive == "base-uri" && value == "'self'":
					features[cspBaseUriSelf] = 1
				case directive == "base-uri":
					features[cspBaseUriCustomURL] = 1
				case directive == "form-action" && value == "'none'":
					features[cspFormActionNone] = 1
				case directive == "form-action" && value == "'self'":
					features[cspFormActionSelf] = 1
				case directive == "form-action":
					features[cspFormActionCustomURL] = 1
				case directive == "frame-ancestors" && value == "'none'":
					features[cspFrameAncestorsNone] = 1
				case directive == "frame-ancestors" && value == "'self'":
					features[cspFrameAncestorsSelf] = 1
				case directive == "frame-ancestors":
					features[cspFrameAncestorsCustomURL] = 1
				case directive == "plugin-types":
					features[cspPluginTypesMimeType] = 1
				case directive == "sandbox":
					features[cspSandbox] = 1
				case directive == "report-uri":
					features[cspReportUriCustomURL] = 1
				case directive == "report-to":
					features[cspReportToCustomGroup] = 1
				default:
					features[cspOtherDirectivesWithCustomURL] = 1
				}
			}
		}
	}

	return features
}

// parseCSP parses a CSP header into a map of directives and values.
func parseCSP(cspHeader string) map[string][]string {
	if strings.TrimSpace(cspHeader) == "" {
		return make(map[string][]string)
	}

	directives := strings.Split(cspHeader, ";")
	parsedCSP := make(map[string][]string)

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		name := parts[0]
		values := parts[1:]

		parsedCSP[name] = values
	}

	return parsedCSP
}

// GenerateCSPVector creates a vector (a slice of float32 values) that represents
// a combination of CSP (content-security-policy) header values. The vector size
// is equal to the number of possible CSP features. In the generated vector, the
// presence of a feature is marked with 1 and the absence is marked with 0.
// The generation of the vector is done in a cryptographically secure way.
func GenerateCSPVector() []float32 {
	// Initialize an empty vector of zeros with a length of cspNumFeatures.
	// Each index in the vector corresponds to a different CSP feature.
	vector := make([]float32, cspNumFeatures)

	// Generate a cryptographically secure random number to decide how many
	// features to include in the vector. The number will be from 0 to cspNumFeatures.
	numFeaturesBig, randErr := rand.Int(rand.Reader, big.NewInt(int64(cspNumFeatures)))
	if randErr != nil {
		log.Fatal("Error generating random number for CSP vector generation")
	}
	numFeatures := int(numFeaturesBig.Int64())

	// Loop over the number of selected features.
	for i := 0; i < numFeatures; i++ {
		// Generate a cryptographically secure random index for the feature to be included.
		// The index will correspond to the position in the vector (and therefore the specific CSP feature).
		indexBig, _ := rand.Int(rand.Reader, big.NewInt(int64(cspNumFeatures)))
		index := int(indexBig.Int64())

		// Mark the selected feature as included in the vector by setting its corresponding position to 1.
		vector[index] = 1
	}

	// Return the generated CSP vector.
	return vector
}
