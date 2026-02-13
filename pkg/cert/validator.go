package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Validator provides certificate and key validation functions
type Validator struct {
	warningDays int
}

// NewValidator creates a new validator with the specified warning days
func NewValidator(warningDays int) *Validator {
	if warningDays <= 0 {
		warningDays = 30
	}
	return &Validator{
		warningDays: warningDays,
	}
}

// ValidateCertificate checks if a certificate is valid
func (v *Validator) ValidateCertificate(certPEM string) (*CertificateInfo, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	remainingDays := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := &CertificateInfo{
		CommonName:         cert.Subject.CommonName,
		SANames:           extractSANames(cert),
		Organization:       extractSubjectOrg(cert),
		OrganizationalUnit: extractSubjectOU(cert),
		Country:           extractSubjectCountry(cert),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		RemainingDays:      remainingDays,
		IsExpired:         now.After(cert.NotAfter),
		IsExpiringSoon:    remainingDays <= v.warningDays,
		Issuer:            getIssuer(cert),
		SerialNumber:       cert.SerialNumber.String(),
		Version:           cert.Version,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Fingerprint:        getFingerprint(cert),
	}

	return info, nil
}

// ValidateCertificatePair checks if a certificate and private key match
func (v *Validator) ValidateCertificatePair(certPEM, keyPEM string) (bool, error) {
	return ValidateCertificateKeyPair(certPEM, keyPEM)
}

// ValidatePrivateKey validates a private key PEM
func (v *Validator) ValidatePrivateKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return err
	case "PRIVATE KEY", "EC PRIVATE KEY":
		_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return err
	case "ECDSA PRIVATE KEY":
		_, err := x509.ParseECPrivateKey(block.Bytes)
		return err
	default:
		return fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// IsExpired checks if a certificate is expired
func (v *Validator) IsExpired(certPEM string) (bool, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return false, err
	}
	return time.Now().After(cert.NotAfter), nil
}

// IsExpiringSoon checks if a certificate is expiring soon
func (v *Validator) IsExpiringSoon(certPEM string) (bool, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return false, err
	}

	remainingDays := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
	return remainingDays <= v.warningDays, nil
}

// GetRemainingDays returns the number of days until expiration
func (v *Validator) GetRemainingDays(certPEM string) (int, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return 0, err
	}

	return int(cert.NotAfter.Sub(time.Now()).Hours() / 24), nil
}

// GetExpirationDate returns the expiration date of a certificate
func (v *Validator) GetExpirationDate(certPEM string) (time.Time, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// ValidateCSR validates a certificate signing request
func ValidateCSR(csrPEM string) error {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM CSR")
	}

	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return fmt.Errorf("PEM block type is not a CSR: %s", block.Type)
	}

	_, err := x509.ParseCertificateRequest(block.Bytes)
	return err
}

// ValidatePEMFormat checks if the content is valid PEM format
func ValidatePEMFormat(content string) error {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}
	return nil
}

// IsPrivateKeyPEM checks if the content is a private key in PEM format
func IsPrivateKeyPEM(content string) bool {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return false
	}

	privateKeyTypes := []string{
		"RSA PRIVATE KEY",
		"PRIVATE KEY",
		"EC PRIVATE KEY",
		"ECDSA PRIVATE KEY",
	}

	for _, keyType := range privateKeyTypes {
		if block.Type == keyType {
			return true
		}
	}

	return false
}

// IsCertificatePEM checks if the content is a certificate in PEM format
func IsCertificatePEM(content string) bool {
	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return false
	}
	return block.Type == "CERTIFICATE"
}

// GetPublicKey extracts the public key from a certificate
func GetPublicKey(certPEM string) (crypto.PublicKey, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey, nil
}

// GetPublicKeyFromKey extracts the public key from a private key
func GetPublicKeyFromKey(keyPEM string) (crypto.PublicKey, error) {
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	switch k := key.(type) {
	case interface{ Public() crypto.PublicKey }:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

// ExtractDomainsFromCertificate extracts all domains from a certificate
func ExtractDomainsFromCertificate(certPEM string) ([]string, error) {
	return GetDomainsFromCertificate(certPEM)
}

// getIssuer extracts the issuer organization from a certificate
func getIssuer(cert *x509.Certificate) string {
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return ""
}

// ValidateDomains checks if all required domains are in the certificate
func ValidateDomains(certPEM string, requiredDomains []string) error {
	domains, err := ExtractDomainsFromCertificate(certPEM)
	if err != nil {
		return err
	}

	domainMap := make(map[string]bool)
	for _, d := range domains {
		domainMap[strings.ToLower(d)] = true
	}

	var missing []string
	for _, req := range requiredDomains {
		if !domainMap[strings.ToLower(req)] {
			missing = append(missing, req)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("certificate missing domains: %v", missing)
	}

	return nil
}

// CheckKeyStrength checks if a key meets minimum strength requirements
func CheckKeyStrength(keyPEM string, minBits int) (int, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return 0, fmt.Errorf("failed to decode PEM key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return 0, err
		}
		bits := key.N.BitLen()
		if minBits > 0 && bits < minBits {
			return bits, fmt.Errorf("key strength %d bits is less than required %d bits", bits, minBits)
		}
		return bits, nil
	case "PRIVATE KEY", "EC PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return 0, err
		}
		switch k := key.(type) {
		case *crypto.PrivateKey:
			// Handle encrypted private key
			return 0, fmt.Errorf("encrypted private key not supported")
		case interface{ Public() crypto.PublicKey }:
			pubKey := k.Public()
			switch pk := pubKey.(type) {
			case interface{ Bits() int }:
				bits := pk.Bits()
				if minBits > 0 && bits < minBits {
					return bits, fmt.Errorf("key strength %d bits is less than required %d bits", bits, minBits)
				}
				return bits, nil
			}
		}
		return 0, fmt.Errorf("unable to determine key strength")
	case "ECDSA PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return 0, err
		}
		bits := key.Curve.Params().BitSize
		if minBits > 0 && bits < minBits {
			return bits, fmt.Errorf("key strength %d bits is less than required %d bits", bits, minBits)
		}
		return bits, nil
	default:
		return 0, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}
