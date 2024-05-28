package users

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//go:embed signing-certificates/intermediate-key-ecdsa.pem signing-certificates/intermediate-cert-ecdsa.pem
var intermediateCAs embed.FS

// JWTManager is used to create and validate JWTs.
type JWTManager struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// NewJWTManager returns a new JWT struct with a signing certificate.
func NewJWTManager() (*JWTManager, error) {
	key, cert, err := generateSigningCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing cert: %w", err)
	}

	return &JWTManager{
		key:  key,
		cert: cert,
	}, nil
}

// JWTClaims holds the claims stored in a JWT.
type JWTClaims struct {
	Username string
	Roles    []int
}

// GenerateToken generates a new JWT for the given user, with the given roles.
// We set the expiry time to 24 hours, and the not before time to now.
func (jm JWTManager) GenerateToken(user string, roles []int) (string, error) {
	// Create the JWT claims, which includes the username and expiry time
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"username": user,
		"roles":    roles,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"nbf":      time.Now().Unix(),
	})

	// Sign the JWT with the private key
	tokenString, err := token.SignedString(jm.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates the given JWT and returns the claims if valid.
func (jm JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Parse the JWT.
	// This will perform signature verification and validation of the claims, such as the
	// expiry time and not before time.
	token, parseErr := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jm.cert.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Name}), jwt.WithJSONNumber())
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", parseErr)
	}

	// Verify the JWT claims
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}

	// Extract the claims
	claims, claimsOk := token.Claims.(jwt.MapClaims)
	if !claimsOk {
		return nil, fmt.Errorf("failed to extract JWT claims")
	}

	// Extract the username
	username, usernameOk := claims["username"].(string)
	if !usernameOk {
		return nil, fmt.Errorf("failed to extract username from JWT claims")
	}

	// Extract the roles
	roles, rolesOk := claims["roles"].([]interface{})
	if !rolesOk {
		return nil, fmt.Errorf("failed to extract roles from JWT claims")
	}

	// Convert the roles to ints
	rolesInts := make([]int, len(roles))
	for i, role := range roles {
		roleInt, roleOk := role.(json.Number)
		if !roleOk {
			return nil, fmt.Errorf("failed to convert role to int")
		}
		roleInt64, roleConvertErr := roleInt.Int64()
		if roleConvertErr != nil {
			return nil, fmt.Errorf("failed to convert role to int: %w", roleConvertErr)
		}
		rolesInts[i] = int(roleInt64)
	}

	// Return the claims
	return &JWTClaims{
		Username: username,
		Roles:    rolesInts,
	}, nil
}

// AddClaimsToContext adds the given claims to the given context.
func (jm JWTManager) AddClaimsToContext(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, "claims", claims)
}

// generateSigningCert generates a new signing certificate for the JWT.
// The signing certificate is signed by the intermediate CA certificate.
func generateSigningCert() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	// Parse the intermediate CA certificate
	intermediateCertPEM, intermediateCertPEMErr := intermediateCAs.ReadFile("signing-certificates/intermediate-cert-ecdsa.pem")
	if intermediateCertPEMErr != nil {
		return nil, nil, fmt.Errorf("failed to read intermediate cert PEM file: %w", intermediateCertPEMErr)
	}
	intermediateCertPEMBlock, _ := pem.Decode(intermediateCertPEM)
	if intermediateCertPEMBlock == nil || intermediateCertPEMBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to parse intermediate cert PEM block")
	}
	intermediateCACert, intermediateCACertErr := x509.ParseCertificate(intermediateCertPEMBlock.Bytes)
	if intermediateCACertErr != nil {
		return nil, nil, fmt.Errorf("failed to parse intermediate CA certificate: %w", intermediateCACertErr)
	}

	// Parse the intermediate CA private key
	intermediateKeyPEM, intermediateKeyPEMErr := intermediateCAs.ReadFile("signing-certificates/intermediate-key-ecdsa.pem")
	if intermediateKeyPEMErr != nil {
		return nil, nil, fmt.Errorf("failed to read intermediate key PEM file: %w", intermediateKeyPEMErr)
	}
	intermediateKeyPEMBlock, _ := pem.Decode(intermediateKeyPEM)
	if intermediateKeyPEMBlock == nil || intermediateKeyPEMBlock.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to parse intermediate key PEM block")
	}
	intermediateCAKey, intermediateCAKeyErr := x509.ParsePKCS8PrivateKey(intermediateKeyPEMBlock.Bytes)
	if intermediateCAKeyErr != nil {
		return nil, nil, fmt.Errorf("failed to parse intermediate CA private key: %w", intermediateCAKeyErr)
	}

	// Verify that the private key is an ECDSA private key
	intermediateCAKeyECDSA, intermediateCAKeyECDSAOk := intermediateCAKey.(*ecdsa.PrivateKey)
	if !intermediateCAKeyECDSAOk {
		return nil, nil, fmt.Errorf("intermediate CA private key is not an ECDSA private key")
	}

	// Generate a leaf certificate
	return generateLeafCert(intermediateCACert, intermediateCAKeyECDSA)
}

// generateLeafCert generates a new leaf certificate for the JWT.
// The leaf certificate is signed by the intermediate CA certificate.
func generateLeafCert(intermediateCACert *x509.Certificate, intermediateCAKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	leafKey, leafKeyGenErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if leafKeyGenErr != nil {
		return nil, nil, fmt.Errorf("failed to generate leaf key: %w", leafKeyGenErr)
	}

	// Generate a sufficiently random large serial number for the certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, randSerialGenerateErr := rand.Int(rand.Reader, serialNumberLimit)
	if randSerialGenerateErr != nil {
		return nil, nil, fmt.Errorf("failed to generate random serial number: %w", randSerialGenerateErr)
	}

	leafCertTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CA"},
			Organization:       []string{"The Hacker Dev"},
			OrganizationalUnit: []string{"JWTManager Signing Service"},
			// Unique common name, which will be presented in the certificate
			// name to the end-user.
			CommonName: "Cartograph Leaf " + hex.EncodeToString(serial.Bytes()),
		},
		// Set to be valid 48 hours before now to prevent "invalid date" errors
		// in browsers.
		NotBefore: time.Now().Add(-48 * time.Hour),
		// Valid for 10 years
		NotAfter: time.Now().AddDate(10, 0, 0),
		// KeyUsage specifies the set of actions that are valid for the
		// provided key. For leaf certificates, we only need to specify
		// KeyUsageDigitalSignature.
		KeyUsage: x509.KeyUsageDigitalSignature,
		// ExtKeyUsage specifies the set of actions that are valid for a given
		// key. For leaf certificates, we only need to specify
		// ExtKeyUsageServerAuth.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// BasicConstraintsValid specifies whether the BasicConstraintsValid
		// field is valid. For leaf certificates, this must be false.
		BasicConstraintsValid: false,
	}

	leafCertDer, leafCertDerErr := x509.CreateCertificate(rand.Reader, leafCertTemplate, intermediateCACert, leafKey.Public(), intermediateCAKey)
	if leafCertDerErr != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %w", leafCertDerErr)
	}

	leafCert, leafCertParseErr := x509.ParseCertificate(leafCertDer)
	if leafCertParseErr != nil {
		return nil, nil, fmt.Errorf("failed to parse leaf certificate: %w", leafCertParseErr)
	}

	return leafKey, leafCert, nil
}
