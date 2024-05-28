// CA-Generator generates both a root and linked intermediate CA, and outputs
// their respective certificate and private key data in PEM-encoded file.
// It will also create a combined certificate containing the intermediate CA's
// certificate first, and then the root CA's certificate afterwards.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// ca holds data about the certificate authority
type ca struct {
	certificate     x509.Certificate
	privateKeyEcdsa *ecdsa.PrivateKey
	privateKeyRsa   *rsa.PrivateKey
}

var (
	// Type of certificate
	isRsa = flag.Bool("rsa", false, "use an RSA key (default is ECDSA)")

	// Output files
	rootCertPEMFile      = flag.String("root-cert-pem", "root-cert.pem", "file location to store root CA PEM-encoded certificate")
	rootCertDERFile      = flag.String("root-cert-der", "root-cert.crt", "file location to store root CA DER-encoded certificate (for use with Android devices)")
	rootKeyFile          = flag.String("root-key", "root-key.pem", "file location to store root CA private key")
	intermediateCertFile = flag.String("intermediate-cert", "intermediate-cert.pem", "file location to store intermediate CA certificate")
	intermediateKeyFile  = flag.String("intermediate-key", "intermediate-key.pem", "file location to store intermediate CA private key")
	combinedCertFile     = flag.String("combined-cert", "combined-cert.pem", "file location to store the combined intermediate and root CA certificates (intermediate goes first in the file")

	// Optional input files
	rootCertInFile = flag.String("root-cert-in", "", "(optional) file location of PEM-encoded root CA certificate")
	rootKeyInFile  = flag.String("root-key-in", "", "(optional) file location of PEM-encoded root CA private key")
)

func main() {
	var rootCA ca
	flag.Parse()

	if *rootCertInFile != "" && *rootKeyInFile != "" {
		// Parse and save the given root certificate and private key
		var parseRootErr error
		rootCA, parseRootErr = parseRootCA(*rootCertInFile, *rootKeyInFile, *rootCertPEMFile, *rootCertDERFile, *rootKeyFile)
		if parseRootErr != nil {
			log.WithError(parseRootErr).Infof("unable to parse the given root CA certificate (%s) and private key (%s); generating new ones instead", *rootCertInFile, *rootKeyInFile)

			// Generate and write the root CA
			var writeRootErr error
			rootCA, writeRootErr = writeRootCA(*rootCertPEMFile, *rootCertDERFile, *rootKeyFile)
			if writeRootErr != nil {
				log.WithError(writeRootErr).Fatalf("unable to generate and write the root CA")
			}
		}
	} else {
		// Generate and write the root CA
		var writeRootErr error
		rootCA, writeRootErr = writeRootCA(*rootCertPEMFile, *rootCertDERFile, *rootKeyFile)
		if writeRootErr != nil {
			log.WithError(writeRootErr).Fatalf("unable to generate and write the root CA")
		}
	}

	// Generate and write the intermediate CA
	if intermediateCAWriteErr := writeIntermediateCA(*intermediateCertFile, *intermediateKeyFile, rootCA); intermediateCAWriteErr != nil {
		log.WithError(intermediateCAWriteErr).Fatalf("unable to generate and write the intermediate CA")
	}

	// Combine the intermediate and root CA certificates into one file, which
	// will be used by every product instance in each group account
	if combinedCertWriteErr := writeCombinedCerts(*intermediateCertFile, *rootCertPEMFile, *combinedCertFile); combinedCertWriteErr != nil {
		log.WithError(combinedCertWriteErr).Fatalf("unable to combine intermediate and root CA certificates into one file")
	}
}

// parseRootCA parses a local PEM-encoded certificate (public key) file and a
// local PEM-encoded private key file for the root CA and returns the data.
// It also writes the data out to the given file locations.
// If the certificate and key files don't exist, it returns an error.
func parseRootCA(rootCertIn, rootKeyIn, rootCertPEMOut, rootCertDEROut, rootKeyOut string) (ca, error) {
	rootCA := ca{}

	// Return an error if the root certificate or key are not provided.
	if rootCertIn == "" || rootKeyIn == "" {
		return ca{}, fmt.Errorf("no root certificate or key file location provided")
	}

	// Read and parse public key (certificate) file
	certPEMData, certReadErr := ioutil.ReadFile(rootCertIn)
	if certReadErr != nil {
		return ca{}, fmt.Errorf("unable to read root CA certificate file %s: %w", rootCertIn, certReadErr)
	}

	// Write the PEM file out
	if pemWriteErr := ioutil.WriteFile(rootCertPEMOut, certPEMData, 0o666); pemWriteErr != nil {
		return ca{}, fmt.Errorf("unable to write PEM-encoded root certificate data to file %s: %w", rootCertPEMOut, pemWriteErr)
	}

	// Decode root certificate PEM data
	rootDER, _ := pem.Decode(certPEMData)
	if rootDER == nil {
		return ca{}, fmt.Errorf("unable to find PEM-encoded data in root CA certificate file %s", rootCertIn)
	}

	// Write the DER file out
	if derWriteErr := ioutil.WriteFile(rootCertDEROut, rootDER.Bytes, 0o666); derWriteErr != nil {
		return ca{}, fmt.Errorf("unable to write DER-encoded root certificate data to file %s: %w", rootCertDEROut, derWriteErr)
	}

	// Store the root CA certificate data
	rootCert, certParseErr := x509.ParseCertificate(rootDER.Bytes)
	if certParseErr != nil {
		return ca{}, fmt.Errorf("unable to parse root CA certificate data from PEM-encoded file %s: %w", rootCertIn, certParseErr)
	}
	rootCA.certificate = *rootCert

	// Read private key
	keyData, keyFileReadErr := ioutil.ReadFile(rootKeyIn)
	if keyFileReadErr != nil {
		return ca{}, fmt.Errorf("unable to read root private key file %s: %w", rootKeyIn, keyFileReadErr)
	}

	// Write private key to file
	if keyWriteErr := ioutil.WriteFile(rootKeyOut, keyData, 0o666); keyWriteErr != nil {
		return ca{}, fmt.Errorf("unable to write root CA private key to file %s: %w", rootKeyOut, keyWriteErr)
	}

	// Decode private key
	keyPEM, _ := pem.Decode(keyData)
	if keyPEM == nil {
		return ca{}, fmt.Errorf("unable to parse root CA private key from PEM-encoded file %s", rootKeyIn)
	} else if keyPEM.Type != "ECDSA PRIVATE KEY" && keyPEM.Type != "EC PRIVATE KEY" && keyPEM.Type != "RSA PRIVATE KEY" && keyPEM.Type != "PRIVATE KEY" {
		return ca{}, fmt.Errorf("invalid root CA private key type %q in file %s; only ECDSA and RSA supported", keyPEM.Type, rootKeyIn)
	}

	// Parse private key and save to ca structure
	if *isRsa {
		// Parse RSA private key
		switch {
		case keyPEM.Type == "RSA PRIVATE KEY":
			key, keyPEMParseErr := x509.ParsePKCS1PrivateKey(keyPEM.Bytes)
			if keyPEMParseErr != nil {
				return ca{}, fmt.Errorf("unable to parse RSA private key from file %s: %w", rootKeyIn, keyPEMParseErr)
			}
			rootCA.privateKeyRsa = key
		case keyPEM.Type == "PRIVATE KEY":
			key, keyPEMParseErr := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
			if keyPEMParseErr != nil {
				return ca{}, fmt.Errorf("unable to parse RSA private key from file %s: %w", rootKeyIn, keyPEMParseErr)
			}
			keyRSA, ok := key.(*rsa.PrivateKey)
			if !ok {
				return ca{}, fmt.Errorf("unable to convert private key interface to RSA private key type")
			}
			rootCA.privateKeyRsa = keyRSA
		default:
			return ca{}, fmt.Errorf("invalid root CA private key type %q in file %s; looking for 'RSA PRIVATE KEY' or 'PRIVATE KEY'", keyPEM.Type, rootKeyIn)
		}
	} else {
		// Parse elliptic curve private key
		switch {
		case keyPEM.Type == "ECDSA PRIVATE KEY" || keyPEM.Type == "EC PRIVATE KEY":
			key, keyPEMParseErr := x509.ParseECPrivateKey(keyPEM.Bytes)
			if keyPEMParseErr != nil {
				return ca{}, fmt.Errorf("unable to parse ECDSA private key from file %s: %w", rootKeyIn, keyPEMParseErr)
			}
			rootCA.privateKeyEcdsa = key
		case keyPEM.Type == "PRIVATE KEY":
			key, keyPEMParseErr := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
			if keyPEMParseErr != nil {
				return ca{}, fmt.Errorf("unable to parse ECDSA private key from file %s: %w", rootKeyIn, keyPEMParseErr)
			}
			keyECDSA, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return ca{}, fmt.Errorf("unable to convert private key interface to ECDSA private key type")
			}
			rootCA.privateKeyEcdsa = keyECDSA
		default:
			return ca{}, fmt.Errorf("invalid root CA private key type %q in file %s; looking for 'ECDSA PRIVATE KEY', 'EC PRIVATE KEY, or 'PRIVATE KEY'", keyPEM.Type, rootKeyIn)
		}
	}

	return rootCA, nil
}

// WriteRootCA generates and writes a certificate and private key for a root CA
// into the given certificate and key files.
//
// It returns the root certificate data for later use in generating an
// intermediate CA certificate.
func writeRootCA(pemCertFileOut, derCertFileOut, keyFileOut string) (ca, error) {
	// Open files into which we will write the root CA data
	rootCertPEMOut, err := os.OpenFile(pemCertFileOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return ca{}, fmt.Errorf("failed to open file %s for writing: %w", pemCertFileOut, err)
	}
	defer handleFileClose(rootCertPEMOut)
	rootCertDEROut, err := os.OpenFile(derCertFileOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return ca{}, fmt.Errorf("failed to open file %s for writing: %w", derCertFileOut, err)
	}
	defer handleFileClose(rootCertDEROut)
	rootKeyOut, err := os.OpenFile(keyFileOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return ca{}, fmt.Errorf("failed to open file %s for writing: %w", keyFileOut, err)
	}
	defer handleFileClose(rootKeyOut)

	// Generate the root CA data and store in the given files
	c, err := createRoot(rootCertPEMOut, rootCertDEROut, rootKeyOut)
	if err != nil {
		return ca{}, fmt.Errorf("unable to create CA certificate and key: %w", err)
	}

	return c, nil
}

// WriteIntermediateCA generates and writes a certificate and private key for
// an intermediate CA into the given certificate and key files. It uses the
// given root CA information to sign and include in its certificate as the
// issuer.
func writeIntermediateCA(certFile, keyFile string, c ca) error {
	// Open files into which we will write the intermediate CA data
	intermediateCertOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %w", certFile, err)
	}
	defer handleFileClose(intermediateCertOut)
	intermediateKeyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %w", keyFile, err)
	}
	defer handleFileClose(intermediateKeyOut)

	// Generate the intermediate CA data and store in the given files
	err = createIntermediate(intermediateCertOut, intermediateKeyOut, c)
	if err != nil {
		return fmt.Errorf("unable to create intermediate CA certificate and key: %w", err)
	}

	return nil
}

// WriteCombinedCerts writes the intermediate CA certificate (first) and the
// root CA certificate (second) into one combined certificate file.
func writeCombinedCerts(intermediateCertFile, rootCertFile, combinedCertFile string) error {
	// Open the root CA certificate file for reading
	rootCertIn, err := os.OpenFile(rootCertFile, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %w", rootCertFile, err)
	}
	defer handleFileClose(rootCertIn)

	// Open the intermediate CA certificate file for reading
	intermediateCertIn, err := os.OpenFile(intermediateCertFile, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %w", intermediateCertFile, err)
	}
	defer handleFileClose(intermediateCertIn)

	// Open the combined certificate file for writing
	combinedCertOut, err := os.OpenFile(combinedCertFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		log.WithError(err).Fatalf("failed to open file %s for writing", combinedCertFile)
	}
	defer handleFileClose(combinedCertOut)

	// Write the intermediate (first) and root (second) certificates into the
	// combined certificate file
	if _, err := io.Copy(combinedCertOut, intermediateCertIn); err != nil {
		return fmt.Errorf("unable to copy intermediate certificate into combined certificate: %w", err)
	}
	if _, err := io.Copy(combinedCertOut, rootCertIn); err != nil {
		return fmt.Errorf("unable to copy root certificate into combined certificate: %w", err)
	}

	return nil
}

// HandleFileClose tries to close the given file. If there is an error, it will
// log it and exit the program.
func handleFileClose(f *os.File) {
	err := f.Close()
	if err != nil {
		log.WithError(err).Fatalf("unable to close file %s", f.Name())
	}
}

// Generate a PEM-encoded block for a given private key.
func pemBlockForKey(key interface{}) *pem.Block {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.WithError(err).Fatal("unable to marshal private key")
	}
	return &pem.Block{Type: "PRIVATE KEY", Bytes: b}
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// CalculateSKID calculates data for a subject key identifier using the
// certificate's own public key.
func calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
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

// CreateRoot generates a new root CA certificate and private key, and outputs
// them to the given io.Writers.
// Returns the root data for signing the next intermediate CA in the chain,
// and any error that may have occurred.
func createRoot(certPEMOut, certDEROut, keyOut io.Writer) (ca, error) {
	var priv interface{}
	var err error
	if *isRsa {
		// Generate RSA private key
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return ca{}, fmt.Errorf("failed to generate RSA private key: %w", err)
		}
	} else {
		// Generate ECDSA private key
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // P256 (recommended), P384, P521
		if err != nil {
			return ca{}, fmt.Errorf("failed to generate ECDSA private key: %w", err)
		}
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if *isRsa {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	// This is a root CA certificate, so it can sign others
	keyUsage |= x509.KeyUsageCertSign

	// The crlSign bit must be set as a root or subordinate CA
	keyUsage |= x509.KeyUsageCRLSign

	// Generate a sufficiently random large serial number for the certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return ca{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Subject key identifier field - unique to this certificate
	skid, err := calculateSKID(publicKey(priv))
	if err != nil {
		return ca{}, fmt.Errorf("unable to generate subject key identifier: %w", err)
	}

	// Root CA certificate template
	rootCATemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CA"},
			Organization:       []string{"The Hacker Dev"},
			OrganizationalUnit: []string{"Root Certificate Authority"},
			// Unique common name, which will be presented in the certificate
			// name to the end-user.
			CommonName: "Cartograph Root CA",
		},
		// Set to be valid 48 hours before now to prevent "invalid date" errors
		// in browsers.
		NotBefore: time.Now().Add(-48 * time.Hour),
		// Valid for 100 years
		NotAfter: time.Now().AddDate(100, 0, 0),

		IsCA: true,
		// Removing maximum path length constraint, as per the CA Browser Forum baseline requirements item 7.1.2.1
		// MaxPathLen:     1,
		MaxPathLenZero: false,

		SubjectKeyId:   skid,
		AuthorityKeyId: skid,

		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}

	// x509 certificate ASN.1-encoded using distinguished encoding rules (DER).
	der, err := x509.CreateCertificate(rand.Reader, &rootCATemplate, &rootCATemplate, publicKey(priv), priv)
	if err != nil {
		return ca{}, fmt.Errorf("failed to create root certificate: %w", err)
	}

	// Write root CA certificate to io.Writer in DER format (for use on Android)
	if _, err := certDEROut.Write(der); err != nil {
		return ca{}, fmt.Errorf("failed to write root CA DER-formatted data to file: %w", err)
	}

	// Write root CA certificate to io.Writer in PEM format
	if err := pem.Encode(certPEMOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return ca{}, fmt.Errorf("failed to write root CA PEM-formatted data to file: %w", err)
	}

	// Write root CA private key to io.Writer
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		return ca{}, fmt.Errorf("failed to write root CA key data to file: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ca{}, fmt.Errorf("unable to parse generated x509 certificate (this should not happen): %w", err)
	}

	if *isRsa {
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return ca{}, fmt.Errorf("did not generate RSA private key")
		}
		return ca{certificate: *cert, privateKeyRsa: rsaPriv}, nil
	} else {
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return ca{}, fmt.Errorf("did not generate ECDSA private key")
		}
		return ca{certificate: *cert, privateKeyEcdsa: ecdsaPriv}, nil
	}
}

// CreateIntermediate generates a new intermediate CA certificate and private
// key, and outputs them to the given io.Writers. The provided root certificate
// is used to sign the intermediate CA certificate.
// Returns any error that may occur.
func createIntermediate(certOut, keyOut io.Writer, c ca) error {
	var priv interface{}
	var err error
	if *isRsa {
		// Generate RSA private key
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA private key: %w", err)
		}
	} else {
		// Generate ECDSA private key
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // P256 (recommended), P384, P521
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA private key: %w", err)
		}
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if *isRsa {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	// This is an intermediate CA certificate, so it can sign others
	keyUsage |= x509.KeyUsageCertSign

	// The crlSign bit must be set as a root or subordinate CA
	keyUsage |= x509.KeyUsageCRLSign

	// Generate a sufficiently random large serial number for the certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Subject key identifier field - unique to this certificate
	skid, err := calculateSKID(publicKey(priv))
	if err != nil {
		return fmt.Errorf("unable to generate subject key identifier: %w", err)
	}

	// Issuing certificate URL
	var issuingCertificateURL []string
	if *isRsa {
		issuingCertificateURL = []string{"https://ca.thehackerdev.com/cartograph-rsa.crt"}
	} else {
		issuingCertificateURL = []string{"https://ca.thehackerdev.com/cartograph-ecdsa.crt"}
	}

	// Intermediate CA certificate template
	intermediateCATemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"CA"},
			Organization:       []string{"The Hacker Dev"},
			OrganizationalUnit: []string{"Intermediate Certificate Authority"},
			// Unique common name, which will be presented in the certificate
			// name to the end-user.
			CommonName: "Cartograph Intermediate CA " + hex.EncodeToString(serial.Bytes()),
		},
		// Set to be valid 48 hours before now to prevent "invalid date" errors
		// in browsers.
		NotBefore: time.Now().Add(-48 * time.Hour),
		// Valid for 100 years
		NotAfter: time.Now().AddDate(100, 0, 0),

		IsCA:           true,
		MaxPathLen:     0,
		MaxPathLenZero: true,

		SubjectKeyId:   skid,
		AuthorityKeyId: c.certificate.AuthorityKeyId,

		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,

		// Required by Mozilla Root Store Policy, section 5.3
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		IssuingCertificateURL: issuingCertificateURL,

		// TODO: Add CRL distribution points here and for root CA
		// CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		// TODO: Add OSCP server here and for root CA
		// OCSPServer: []string{"https://oscp.thehackerdev.com"},

		// TODO: Add in link to root CA's certificate policies, certification practice statement, relying party agreement, and other policy information, for both this and for root CA. More details: https://www.sysadmins.lv/blog-en/certificate-policies-extension-all-you-should-know-part-1.aspx.
		// PolicyIdentifiers: ,
	}

	// x509 certificate ASN.1-encoded using distinguished encoding rules (DER).
	var derCert []byte
	if *isRsa {
		derCert, err = x509.CreateCertificate(rand.Reader, &intermediateCATemplate, &c.certificate, publicKey(priv), c.privateKeyRsa)
		if err != nil {
			return fmt.Errorf("failed to create intermediate certificate: %w", err)
		}
	} else {
		derCert, err = x509.CreateCertificate(rand.Reader, &intermediateCATemplate, &c.certificate, publicKey(priv), c.privateKeyEcdsa)
		if err != nil {
			return fmt.Errorf("failed to create intermediate certificate: %w", err)
		}
	}

	// Write intermediate CA certificate to io.Writer
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derCert}); err != nil {
		return fmt.Errorf("failed to write intermediate CA PEM-formatted data to file: %s", err)
	}

	// Write intermediate CA private key to io.Writer
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		return fmt.Errorf("failed to write intermediate CA key data to file: %s", err)
	}

	return nil
}

// TODO: Add linting tests with zlint: https://github.com/zmap/zlint
