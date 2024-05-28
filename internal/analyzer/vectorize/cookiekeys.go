package vectorize

import (
	"crypto/rand"
	"math/big"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/TheHackerDev/cartograph/internal/analyzer/vectorize/bagofwords"
)

// cookiekeys.go contains the code to vectorize HTTP cookie keys.

var cookieKeysMap map[string]int

func init() {
	// Convert the cookie keys to a map for faster lookup, where the value is the index in the vector.
	cookieKeysMap = make(map[string]int, len(bagofwords.CookieKeys))
	for i, cookie := range bagofwords.CookieKeys {
		cookieKeysMap[cookie] = i
	}
}

// CookieKeys converts the given slice of cookie keys to a vector.
func CookieKeys(keys []string) []float32 {
	vector := make([]float32, len(bagofwords.CookieKeys))

	// Loop through cookies in the request and update the vector
	for _, cookie := range keys {
		if index, ok := cookieKeysMap[strings.ToLower(cookie)]; ok {
			vector[index] = 1
		}
	}

	// Loop through the cookies in the response and update the vector
	for _, cookie := range keys {
		if index, ok := cookieKeysMap[strings.ToLower(cookie)]; ok {
			vector[index] = 1
		}
	}

	return vector
}

// GenerateCookieKeysVector generates a vector of cookie keys for testing purposes.
// The vector is generated by randomly selecting a number of cookie keys from the list of cookie keys, up to the max
// number of cookie keys.
func GenerateCookieKeysVector() []float32 {
	maxCookieKeys := 14

	vector := make([]float32, len(bagofwords.CookieKeys))

	// Randomly select a number of cookie keys to add to the vector, up to the max number of cookie keys
	numCookieKeys, randErrSmall := rand.Int(rand.Reader, big.NewInt(int64(maxCookieKeys)))
	if randErrSmall != nil {
		log.Fatal("Error generating random number for cookie keys vector generation")
	}

	for i := int64(0); i < numCookieKeys.Int64(); i++ {
		// Randomly select a cookie key to add to the vector
		cookieKeyIndex, randErrBig := rand.Int(rand.Reader, big.NewInt(int64(len(bagofwords.CookieKeys))))
		if randErrBig != nil {
			log.Fatal("Error generating random number for cookie keys vector generation")
		}

		vector[cookieKeyIndex.Int64()] = 1
	}

	return vector
}