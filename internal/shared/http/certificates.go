package http

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

//go:embed certificates/*
var caCerts embed.FS

func init() {
	// Write the root CA certificates to the filesystem
	if writeRootCertsErr := writeRootCertsAndKeysToFs(); writeRootCertsErr != nil {
		log.Fatalf("unable to write root CA certificates to filesystem: %v", writeRootCertsErr)
	}
}

// NewCertificateManager returns a new CertificateManager object.
//
// Any errors returned should be considered fatal.
func NewCertificateManager() (*CertificateManager, error) {
	certificates := &CertificateManager{
		certMap: &certMap{
			certs: make(map[string]*tls.Certificate),
		},
	}

	// Parse the embedded certificate authority certificate and private key files (root and intermediate CAs)
	caData, parseCAsErr := certificates.parseCAs()
	if parseCAsErr != nil {
		return nil, parseCAsErr
	}
	certificates.ca = &caData

	return certificates, nil
}

// CertificateManager is a struct that manages TLS certificates generated on the fly.
type CertificateManager struct {
	// certMap is a map of top-level hosts to a created TLS certificate.
	certMap *certMap

	// ca is the certificate authority used to sign dynamically generated TLS certificates.
	ca *certificateAuthority
}

// certMap holds data about dynamically generated TLS certificates, and allows for safe concurrent writes through a mutex.
type certMap struct {
	sync.RWMutex

	// certs maps top-level hosts to a created TLS certificate.
	certs map[string]*tls.Certificate
}

// certificateAuthority holds data about the certificate chain, all the way to the root certificate.
// It is used when generating new TLS certificates in order to provide all certificate data up the chain.
type certificateAuthority struct {
	// intermediateCertEcdsa is the CA's x509 certificate (using ECDSA encryption), which is used as the parent certificate when creating another certificate using x509's CreateCertificate function.
	intermediateCertEcdsa x509.Certificate

	// intermediateCertRsa is the CA's x509 certificate (using RSA encryption), which is used as the parent certificate when creating another certificate using x509's CreateCertificate function.
	intermediateCertRsa x509.Certificate

	// rootCertEcdsa is the root CA certificate (using ECDSA encryption).
	rootCertEcdsa x509.Certificate

	// rootCertRsa is the root CA certificate (using RSA encryption).
	rootCertRsa x509.Certificate

	// intermediateKeyEcdsa is the intermediate CA's private key (using ECDSA encryption) which is used as the signing key when creating another certificate using x509's CreateCertificate function.
	intermediateKeyEcdsa *ecdsa.PrivateKey

	// intermediateKeyRsa is the intermediate CA's private key (using RSA encryption) which is used as the signing key when creating another certificate using x509's CreateCertificate function.
	intermediateKeyRsa *rsa.PrivateKey
}

// parseCAs parses the embedded certificate authority certificate and private key files (root and intermediate CAs) and
// returns a data structure containing their data.
// This data is then used in dynamic certificate generation.
// Any errors returned should be considered fatal.
func (c *CertificateManager) parseCAs() (certificateAuthority, error) {
	var ca certificateAuthority

	// Root CA certificate (RSA)
	rootCertRsaRaw, rootCertRsaReadErr := caCerts.ReadFile("certificates/root-cert-rsa.pem")
	if rootCertRsaReadErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to read embedded RSA root CA certificate: %w", rootCertRsaReadErr)
	}
	rootPemRsa, _ := pem.Decode(rootCertRsaRaw)
	if rootPemRsa == nil {
		return certificateAuthority{}, fmt.Errorf("unable to decode embedded RSA root CA certificate")
	}
	rootCertRsa, rootCertRsaParseErr := x509.ParseCertificate(rootPemRsa.Bytes)
	if rootCertRsaParseErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to parse embedded RSA root CA certificate: %w", rootCertRsaParseErr)
	}
	ca.rootCertRsa = *rootCertRsa

	// Root CA certificate (ECDSA)
	rootCertEcdsaRaw, rootCertEcdsaReadErr := caCerts.ReadFile("certificates/root-cert-ecdsa.pem")
	if rootCertEcdsaReadErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to read embedded ECDSA root CA certificate: %w", rootCertEcdsaReadErr)
	}
	rootPemEcdsa, _ := pem.Decode(rootCertEcdsaRaw)
	if rootPemEcdsa == nil {
		return certificateAuthority{}, fmt.Errorf("unable to decode embedded ECDSA root CA certificate")
	}
	rootCertEcdsa, rootCertEcdsaParseErr := x509.ParseCertificate(rootPemEcdsa.Bytes)
	if rootCertEcdsaParseErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to parse embedded ECDSA root CA certificate: %w", rootCertEcdsaParseErr)
	}
	ca.rootCertEcdsa = *rootCertEcdsa

	// Intermediate CA certificate (RSA)
	intermediateCertRawRsa, intermediateCertRsaReadErr := caCerts.ReadFile("certificates/intermediate-cert-rsa.pem")
	if intermediateCertRsaReadErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to read embedded RSA intermediate CA certificate: %w", intermediateCertRsaReadErr)
	}
	intermediateCertPemRsa, _ := pem.Decode(intermediateCertRawRsa)
	if intermediateCertPemRsa == nil {
		return certificateAuthority{}, fmt.Errorf("unable to decode embedded RSA intermediate CA certificate")
	}
	intermediateCertRsa, intermediateCertRsaParseErr := x509.ParseCertificate(intermediateCertPemRsa.Bytes)
	if intermediateCertRsaParseErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to parse embedded RSA intermediate CA certificate: %w", intermediateCertRsaParseErr)
	}
	ca.intermediateCertRsa = *intermediateCertRsa

	// Intermediate CA certificate (ECDSA)
	intermediateCertRawEcdsa, intermediateCertEcdsaReadErr := caCerts.ReadFile("certificates/intermediate-cert-ecdsa.pem")
	if intermediateCertEcdsaReadErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to read embedded ECDSA intermediate CA certificate: %w", intermediateCertEcdsaReadErr)
	}
	intermediateCertPemEcdsa, _ := pem.Decode(intermediateCertRawEcdsa)
	if intermediateCertPemEcdsa == nil {
		return certificateAuthority{}, fmt.Errorf("unable to decode embedded ECDSA intermediate CA certificate")
	}
	intermediateCertEcdsa, intermediateCertEcdsaParseErr := x509.ParseCertificate(intermediateCertPemEcdsa.Bytes)
	if intermediateCertEcdsaParseErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to parse embedded ECDSA intermediate CA certificate: %w", intermediateCertEcdsaParseErr)
	}
	ca.intermediateCertEcdsa = *intermediateCertEcdsa

	// Intermediate CA private key (ECDSA)
	intermediateKeyEcdsaRaw, intermediateKeyEcdsaReadErr := caCerts.ReadFile("certificates/intermediate-key-ecdsa.pem")
	if intermediateKeyEcdsaReadErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to read embedded ECDSA intermediate CA private key: %w", intermediateKeyEcdsaReadErr)
	}
	intermediateKeyEcdsaPem, _ := pem.Decode(intermediateKeyEcdsaRaw)
	if intermediateKeyEcdsaPem == nil {
		return certificateAuthority{}, fmt.Errorf("unable to decode embedded ECDSA intermediate CA private key")
	}
	switch {
	case intermediateKeyEcdsaPem.Type == "ECDSA PRIVATE KEY" || intermediateKeyEcdsaPem.Type == "EC PRIVATE KEY":
		intermediateKeyEcdsa, keyPEMParseErr := x509.ParseECPrivateKey(intermediateKeyEcdsaPem.Bytes)
		if keyPEMParseErr != nil {
			return certificateAuthority{}, fmt.Errorf("unable to parse embedded intermediate CA private key: %w", keyPEMParseErr)
		}
		ca.intermediateKeyEcdsa = intermediateKeyEcdsa
	case intermediateKeyEcdsaPem.Type == "PRIVATE KEY":
		intermediateKey, keyPEMParseErr := x509.ParsePKCS8PrivateKey(intermediateKeyEcdsaPem.Bytes)
		if keyPEMParseErr != nil {
			return certificateAuthority{}, fmt.Errorf("unable to parse embedded ECDSA intermediate CA private key: %w", keyPEMParseErr)
		}
		intermediateKeyEcdsa, ok := intermediateKey.(*ecdsa.PrivateKey)
		if !ok {
			return certificateAuthority{}, fmt.Errorf("unable to convert private key interface to ECDSA private key type for intermediate CA")
		}
		ca.intermediateKeyEcdsa = intermediateKeyEcdsa
	default:
		return certificateAuthority{}, fmt.Errorf("invalid ECDSA intermediate CA private key type %s", intermediateKeyEcdsaPem.Type)
	}

	// Intermediate CA private key (RSA)
	intermediateKeyRsaRaw, intermediateKeyRsaReadErr := caCerts.ReadFile("certificates/intermediate-key-rsa.pem")
	if intermediateKeyRsaReadErr != nil {
		return certificateAuthority{}, fmt.Errorf("unable to read embedded RSA intermediate CA private key: %w", intermediateKeyRsaReadErr)
	}
	intermediateKeyRsaPem, _ := pem.Decode(intermediateKeyRsaRaw)
	if intermediateKeyRsaPem == nil {
		return certificateAuthority{}, fmt.Errorf("unable to decode embedded RSA intermediate CA private key")
	}
	switch {
	case intermediateKeyRsaPem.Type == "RSA PRIVATE KEY":
		intermediateKeyRsa, keyPEMParseErr := x509.ParsePKCS1PrivateKey(intermediateKeyRsaPem.Bytes)
		if keyPEMParseErr != nil {
			return certificateAuthority{}, fmt.Errorf("unable to parse embedded RSA intermediate CA private key: %w", keyPEMParseErr)
		}
		ca.intermediateKeyRsa = intermediateKeyRsa
	case intermediateKeyRsaPem.Type == "PRIVATE KEY":
		intermediateKey, keyPEMParseErr := x509.ParsePKCS8PrivateKey(intermediateKeyRsaPem.Bytes)
		if keyPEMParseErr != nil {
			return certificateAuthority{}, fmt.Errorf("unable to parse embedded RSA intermediate CA private key: %w", keyPEMParseErr)
		}
		intermediateKeyRsa, ok := intermediateKey.(*rsa.PrivateKey)
		if !ok {
			return certificateAuthority{}, fmt.Errorf("unable to convert private key interface to RSA private key type for intermediate CA")
		}
		ca.intermediateKeyRsa = intermediateKeyRsa
	default:
		return certificateAuthority{}, fmt.Errorf("invalid intermediate CA private key type %s", intermediateKeyRsaPem.Type)
	}

	return ca, nil
}

// writeRootCertsAndKeysToFs writes the root CA certificates and keys to the filesystem.
// This makes it easy for the user to install the root CA certificates in their trust store.
// These keys will also be reused when generating new certificates.
// Any errors returned should be considered fatal.
func writeRootCertsAndKeysToFs() error {
	rootCertPemRsaFilename := "root-cert-rsa.pem"
	rootKeyPemRsaFilename := "root-key-rsa.pem"
	rootCertDerRsaFilename := "root-cert-rsa.crt"
	rootCertPemEcdsaFilename := "root-cert-ecdsa.pem"
	rootKeyPemEcdsaFilename := "root-key-ecdsa.pem"
	rootCertDerEcdsaFilename := "root-cert-ecdsa.crt"

	// Read the root CA certificates and keys from the embedded filesystem
	rootCertPemRsaRaw, rootCertPemRsaReadErr := caCerts.ReadFile(fmt.Sprintf("certificates/%s", rootCertPemRsaFilename))
	if rootCertPemRsaReadErr != nil {
		return fmt.Errorf("unable to read embedded PEM-formatted RSA root CA certificate: %w", rootCertPemRsaReadErr)
	}
	rootCertDerRsaRaw, rootCertDerRsaReadErr := caCerts.ReadFile(fmt.Sprintf("certificates/%s", rootCertDerRsaFilename))
	if rootCertDerRsaReadErr != nil {
		return fmt.Errorf("unable to read embedded DER-formatted RSA root CA certificate: %w", rootCertDerRsaReadErr)
	}
	rootCertPemEcdsaRaw, rootCertPemEcdsaReadErr := caCerts.ReadFile(fmt.Sprintf("certificates/%s", rootCertPemEcdsaFilename))
	if rootCertPemEcdsaReadErr != nil {
		return fmt.Errorf("unable to read embedded PEM-formatted ECDSA root CA certificate: %w", rootCertPemEcdsaReadErr)
	}
	rootCertDerEcdsaRaw, rootCertDerEcdsaReadErr := caCerts.ReadFile(fmt.Sprintf("certificates/%s", rootCertDerEcdsaFilename))
	if rootCertDerEcdsaReadErr != nil {
		return fmt.Errorf("unable to read embedded DER-formatted ECDSA root CA certificate: %w", rootCertDerEcdsaReadErr)
	}
	rootKeyPemRsaRaw, rootKeyPemRsaReadErr := caCerts.ReadFile(fmt.Sprintf("certificates/%s", rootKeyPemRsaFilename))
	if rootKeyPemRsaReadErr != nil {
		return fmt.Errorf("unable to read embedded PEM-formatted RSA root CA private key: %w", rootKeyPemRsaReadErr)
	}
	rootKeyPemEcdsaRaw, rootKeyPemEcdsaReadErr := caCerts.ReadFile(fmt.Sprintf("certificates/%s", rootKeyPemEcdsaFilename))
	if rootKeyPemEcdsaReadErr != nil {
		return fmt.Errorf("unable to read embedded PEM-formatted ECDSA root CA private key: %w", rootKeyPemEcdsaReadErr)
	}

	// Write the root CA certificates and keys to the filesystem
	osCertPath := "/ca-certificates"
	rootCertPemRsaWriteErr := os.WriteFile(fmt.Sprintf("%s/%s", osCertPath, rootCertPemRsaFilename), rootCertPemRsaRaw, 0o666)
	if rootCertPemRsaWriteErr != nil {
		return fmt.Errorf("unable to write PEM-formatted RSA root CA certificate to filesystem: %w", rootCertPemRsaWriteErr)
	}
	rootCertDerRsaWriteErr := os.WriteFile(fmt.Sprintf("%s/%s", osCertPath, rootCertDerRsaFilename), rootCertDerRsaRaw, 0o666)
	if rootCertDerRsaWriteErr != nil {
		return fmt.Errorf("unable to write DER-formatted RSA root CA certificate to filesystem: %w", rootCertDerRsaWriteErr)
	}
	rootCertPemEcdsaWriteErr := os.WriteFile(fmt.Sprintf("%s/%s", osCertPath, rootCertPemEcdsaFilename), rootCertPemEcdsaRaw, 0o666)
	if rootCertPemEcdsaWriteErr != nil {
		return fmt.Errorf("unable to write PEM-formatted ECDSA root CA certificate to filesystem: %w", rootCertPemEcdsaWriteErr)
	}
	rootCertDerEcdsaWriteErr := os.WriteFile(fmt.Sprintf("%s/%s", osCertPath, rootCertDerEcdsaFilename), rootCertDerEcdsaRaw, 0o666)
	if rootCertDerEcdsaWriteErr != nil {
		return fmt.Errorf("unable to write DER-formatted ECDSA root CA certificate to filesystem: %w", rootCertDerEcdsaWriteErr)
	}
	rootKeyPemRsaWriteErr := os.WriteFile(fmt.Sprintf("%s/%s", osCertPath, rootKeyPemRsaFilename), rootKeyPemRsaRaw, 0o666)
	if rootKeyPemRsaWriteErr != nil {
		return fmt.Errorf("unable to write PEM-formatted RSA root CA private key to filesystem: %w", rootKeyPemRsaWriteErr)
	}
	rootKeyPemEcdsaWriteErr := os.WriteFile(fmt.Sprintf("%s/%s", osCertPath, rootKeyPemEcdsaFilename), rootKeyPemEcdsaRaw, 0o666)
	if rootKeyPemEcdsaWriteErr != nil {
		return fmt.Errorf("unable to write PEM-formatted ECDSA root CA private key to filesystem: %w", rootKeyPemEcdsaWriteErr)
	}

	// Print the paths to the user
	log.Infof("Root CA certificates written to %s\n", osCertPath)

	return nil
}

// GetCertificateDynamic generates dynamic TLS certificates for incoming HTTPS connections.
func (c *CertificateManager) GetCertificateDynamic() func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// Verify that the client uses SNI (only very old clients, like Windows XP won't support it), and includes the "host" field.
		serverName := strings.ToLower(info.ServerName)
		if serverName == "" {
			return nil, fmt.Errorf("empty SNI \"host\" field not supported")
		}

		// Check for existing certificates matching the parent host
		sans := c.getSANs(serverName)
		c.certMap.RLock()
		if cert, found := c.certMap.certs[sans.parent]; found {
			c.certMap.RUnlock()
			return cert, nil
		}
		c.certMap.RUnlock()

		// Generate a new ECDSA leaf certificate for the host and wildcards
		leafCert, newLeafCertErr := c.generateLeafCertificateEcdsa(sans)
		if newLeafCertErr != nil {
			return nil, fmt.Errorf("unable to generate ECDSA leaf certificate for parent host (%s): %w", sans.parent, newLeafCertErr)
		}

		// Verify that the client supports the certificate we generated
		if certSupportErr := info.SupportsCertificate(leafCert); certSupportErr != nil {
			// ECDSA certificate not supported; generate an RSA certificate
			var newRsaLeafCertErr error
			leafCert, newRsaLeafCertErr = c.generateLeafCertificateRsa(sans)
			if newRsaLeafCertErr != nil {
				return nil, fmt.Errorf("unable to generate RSA leaf certificate for parent host (%s): %w", sans.parent, newRsaLeafCertErr)
			}

			// Verify that the client supports the RSA certificate instead
			if rsaCertSupportErr := info.SupportsCertificate(leafCert); rsaCertSupportErr != nil {
				return nil, fmt.Errorf("client does not support generated ECDSA or RSA leaf certificates: %w", certSupportErr)
			}
		}

		// Save the certificate in the certificate map
		c.certMap.Lock()
		c.certMap.certs[sans.parent] = leafCert
		c.certMap.Unlock()

		return leafCert, nil
	}
}

// wildcards holds the wildcard host information for use with generated TLS certificates.
type wildcards struct {
	parent  string
	domains []string
	ip      string
}

// getSANs returns a list of values to be used for the subject alternative name (SAN) field of the TLS certificate.
// This includes the parent domain, which is used for indexing in the in-memory certificate store, as well as a list of domains and IPs to use in the SAN field.
//
// For example: "www.example.com" creates just "*.example.com"; "abc.def.example.com" creates both "*.def.example.com" AND "*.example.com".
// This is because SANs only support a single level of subdomain per wildcard.
//
// Provided host may be a domain or an IP address.
func (c *CertificateManager) getSANs(host string) wildcards {
	if host == "" {
		return wildcards{
			parent:  host,
			domains: []string{host},
			ip:      "",
		}
	}

	// Check if it's an IP
	noPort := strings.Split(host, ":")[0]
	if ip := net.ParseIP(noPort); ip != nil {
		return wildcards{
			parent:  ip.String(),
			domains: nil,
			ip:      ip.String(),
		}
	}

	// Separate out the sections of the given host domain
	h := strings.Split(host, ".")
	switch len(h) {
	case 1:
		// No domain provided, just one word (e.g. "localhost")
		return wildcards{
			parent:  host,
			domains: []string{fmt.Sprintf("*.%s", host), host},
			ip:      "",
		}
	case 2:
		// Top level domain provided
		return wildcards{
			parent:  host,
			domains: []string{fmt.Sprintf("*.%s", strings.Join(h, ".")), host},
			ip:      "",
		}
	}
	// 3 or more domains provided; only provide wildcards for the host and its parent domain.
	hosts := wildcards{
		parent:  strings.Join(h[1:], "."),
		domains: []string{},
		ip:      "",
	}
	for i := 0; i < 2; i++ {
		// Provide an entry for the host and a wildcard for its subdomains
		full := strings.Join(h[i:], ".")
		wildcard := "*." + full
		hosts.domains = append(hosts.domains, wildcard, full)
	}
	return hosts
}

// generateLeafCertificateEcdsa generates a new ECDSA TLS certificate that is valid for the given set of hosts.
// It uses the provided CA certificate chain information to sign the certificate.
func (c *CertificateManager) generateLeafCertificateEcdsa(hosts wildcards) (*tls.Certificate, error) {
	// Generate ECDSA private key
	privKey, keyGenErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // P256 (recommended), P384, P521
	if keyGenErr != nil {
		return nil, fmt.Errorf("unable to generate ECDSA private key: %w", keyGenErr)
	}

	// Generate a sufficiently random large serial number for the certificate
	serial, bigRandErr := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if bigRandErr != nil {
		return nil, fmt.Errorf("failed to generate serial number for ECDSA certificate: %w", bigRandErr)
	}

	// Subject key identifier field - unique to this leaf certificate
	skid, skidErr := c.calculateSKID(&privKey.PublicKey)
	if skidErr != nil {
		return nil, fmt.Errorf("unable to calculate subject key identifier for ECDSA certificate: %w", skidErr)
	}

	// Check for empty parent host
	if hosts.parent == "" {
		return nil, fmt.Errorf("no host provided for certificate")
	}

	// x509 leaf certificate
	leafTemplate := x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		SerialNumber:       serial,
		Subject: pkix.Name{
			Country:            []string{"CA"},
			Organization:       []string{"The Hacker Dev"},
			OrganizationalUnit: []string{"Cartograph"},

			// Parent host used as common name.
			// This exists for legacy clients that do not check for subject alternative name (SAN) field.
			// DEPRECATED: This is no longer applicable, see RFC 2818.
			CommonName: hosts.parent,
		},

		// Set to be valid 24 hours before now to prevent "invalid date" errors in browsers
		NotBefore: time.Now().Add(-24 * time.Hour),
		// Valid for 825 days, the most accepted by OSX Catalina, and now other more strict sources.
		NotAfter: time.Now().AddDate(0, 0, 820),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  false,

		SubjectKeyId:   skid,
		AuthorityKeyId: c.ca.intermediateCertEcdsa.SubjectKeyId,

		// OCSPServer:                  nil,
		// IssuingCertificateURL:       nil,

		// DNSNames:                    nil,
		// EmailAddresses:              nil,
		// IPAddresses:                 nil,
		// URIs:                        nil,
	}

	// Set subject alternative names (SANs)
	leafTemplate.DNSNames = append(leafTemplate.DNSNames, hosts.domains...)
	if hosts.ip != "" {
		leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, net.ParseIP(hosts.ip))
	}

	// Create the ASN.1-encoded x509 certificate, using the distinguished encoding rules (DER)
	leafCert, createCertErr := x509.CreateCertificate(rand.Reader, &leafTemplate, &c.ca.intermediateCertEcdsa, &privKey.PublicKey, c.ca.intermediateKeyEcdsa)
	if createCertErr != nil {
		return nil, fmt.Errorf("unable to create final ECDSA leaf certificate: %w", createCertErr)
	}

	// Create a certificate chain using leaf, intermediate, and root certificates
	return &tls.Certificate{
		Certificate: [][]byte{leafCert, c.ca.intermediateCertEcdsa.Raw, c.ca.rootCertEcdsa.Raw},
		PrivateKey:  privKey,
		// SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		// OCSPStaple:                   nil,
		// SignedCertificateTimestamps:  nil,
	}, nil
}

// generateLeafCertificateRsa generates a new RSA TLS certificate that is valid for the given set of hosts.
// It uses the provided CA certificate chain information to sign the certificate.
func (c *CertificateManager) generateLeafCertificateRsa(hosts wildcards) (*tls.Certificate, error) {
	// Generate RSA private key
	privKey, keyGenErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyGenErr != nil {
		return nil, fmt.Errorf("unable to generate RSA private key: %w", keyGenErr)
	}

	// Generate a sufficiently random large serial number for the certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, bigRandErr := rand.Int(rand.Reader, serialNumberLimit)
	if bigRandErr != nil {
		return nil, fmt.Errorf("failed to generate serial number for RSA certificate: %w", bigRandErr)
	}

	// Subject key identifier field - unique to this leaf certificate
	skid, skidErr := c.calculateSKID(&privKey.PublicKey)
	if skidErr != nil {
		return nil, fmt.Errorf("unable to calculate subject key identifier for RSA certificate: %w", skidErr)
	}

	// Check for empty parent host
	if hosts.parent == "" {
		return nil, fmt.Errorf("no host provided for certificate")
	}

	// x509 leaf certificate
	leafTemplate := x509.Certificate{
		PublicKeyAlgorithm: x509.RSA,
		SerialNumber:       serial,
		Subject: pkix.Name{
			Country:            []string{"CA"},
			Organization:       []string{"The Hacker Dev"},
			OrganizationalUnit: []string{"Cartograph"},

			// Parent host used as common name.
			// This exists for legacy clients that do not check for subject alternative name (SAN) field.
			// DEPRECATED: This is no longer applicable, see RFC 2818.
			CommonName: hosts.parent,
		},

		// Set to be valid 24 hours before now to prevent "invalid date" errors in browsers
		NotBefore: time.Now().Add(-24 * time.Hour),
		// Valid for 825 days, the most accepted by OSX Catalina, and now other more strict sources.
		NotAfter: time.Now().AddDate(0, 0, 820),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  false,

		SubjectKeyId:   skid,
		AuthorityKeyId: c.ca.intermediateCertRsa.SubjectKeyId,

		// OCSPServer:                  nil,
		// IssuingCertificateURL:       nil,

		// DNSNames:                    nil,
		// EmailAddresses:              nil,
		// IPAddresses:                 nil,
		// URIs:                        nil,
	}

	// Set subject alternative names (SANs)
	leafTemplate.DNSNames = append(leafTemplate.DNSNames, hosts.domains...)
	if hosts.ip != "" {
		leafTemplate.IPAddresses = append(leafTemplate.IPAddresses, net.ParseIP(hosts.ip))
	}

	// Create the ASN.1-encoded x509 certificate, using the distinguished encoding rules (DER)
	leafCert, createCertErr := x509.CreateCertificate(rand.Reader, &leafTemplate, &c.ca.intermediateCertRsa, &privKey.PublicKey, c.ca.intermediateKeyRsa)
	if createCertErr != nil {
		return nil, fmt.Errorf("unable to create final RSA leaf certificate: %w", createCertErr)
	}

	// Create a certificate chain using leaf, intermediate, and root certificates
	return &tls.Certificate{
		Certificate: [][]byte{leafCert, c.ca.intermediateCertRsa.Raw, c.ca.rootCertRsa.Raw},
		PrivateKey:  privKey,
		// OCSPStaple:                   nil,
		// SignedCertificateTimestamps:  nil,
	}, nil
}

// calculateSKID calculates data for a subject key identifier using the certificate's own public key.
func (c *CertificateManager) calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
	spkiASN1, marshalErr := x509.MarshalPKIXPublicKey(pubKey)
	if marshalErr != nil {
		return nil, fmt.Errorf("unable to marshal public key to subject PKI ASN1 byte array: %w", marshalErr)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, unmarshalErr := asn1.Unmarshal(spkiASN1, &spki); unmarshalErr != nil {
		return nil, fmt.Errorf("unable to unmarshal ASN1 subject PKI data to subject PKI data structure: %w", unmarshalErr)
	}
	h := crypto.SHA256.New()
	skid := h.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:], nil
}
