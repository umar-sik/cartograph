package users

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2ID holds the data used to create the Argon2ID hash.
type Argon2ID struct {
	format  string
	version int
	time    uint32
	memory  uint32
	keyLen  uint32
	saltLen uint32
	threads uint8
}

// NewArgon2ID returns a new Argon2ID struct with strong default parameters.
func NewArgon2ID() Argon2ID {
	return Argon2ID{
		format:  "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		version: argon2.Version,
		time:    1,
		memory:  64 * 1024,
		keyLen:  32,
		saltLen: 16,
		threads: 4,
	}
}

// Hash returns the Argon2ID hash of the plain text password.
func (a Argon2ID) Hash(plain string) (string, error) {
	salt := make([]byte, a.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(plain), salt, a.time, a.memory, a.threads, a.keyLen)

	return fmt.Sprintf(
			a.format,
			a.version,
			a.memory,
			a.time,
			a.threads,
			base64.RawStdEncoding.EncodeToString(salt),
			base64.RawStdEncoding.EncodeToString(hash),
		),
		nil
}

// Verify returns true if the plain text password matches the hash.
func (a Argon2ID) Verify(plain, hash string) (bool, error) {
	hashParts := strings.Split(hash, "$")

	_, configParseErr := fmt.Sscanf(hashParts[3], "m=%d,t=%d,p=%d", &a.memory, &a.time, &a.threads)
	if configParseErr != nil {
		return false, configParseErr
	}

	salt, saltDecodeErr := base64.RawStdEncoding.DecodeString(hashParts[4])
	if saltDecodeErr != nil {
		return false, saltDecodeErr
	}

	decodedHash, passwordHashDecodeErr := base64.RawStdEncoding.DecodeString(hashParts[5])
	if passwordHashDecodeErr != nil {
		return false, passwordHashDecodeErr
	}

	hashToCompare := argon2.IDKey([]byte(plain), salt, a.time, a.memory, a.threads, uint32(len(decodedHash)))

	// Compare the hashes in constant time to prevent timing attacks
	return subtle.ConstantTimeCompare(decodedHash, hashToCompare) == 1, nil
}
