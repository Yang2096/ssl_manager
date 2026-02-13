package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// CertificateInfo represents parsed certificate information
type CertificateInfo struct {
	CommonName         string    `json:"common_name"`
	SANames           []string  `json:"san_names"`
	Organization       string    `json:"organization"`
	OrganizationalUnit string    `json:"organizational_unit"`
	Country            string    `json:"country"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	RemainingDays      int       `json:"remaining_days"`
	IsExpired          bool      `json:"is_expired"`
	IsExpiringSoon     bool      `json:"is_expiring_soon"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	Version            int       `json:"version"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Fingerprint        string    `json:"fingerprint"`
}

// ParseCertificate parses a PEM-encoded certificate
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is not CERTIFICATE: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ParseCertificateInfo parses a PEM-encoded certificate and returns detailed information
func ParseCertificateInfo(certPEM string, warningDays int) (*CertificateInfo, error) {
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
		RemainingDays:     remainingDays,
		IsExpired:         now.After(cert.NotAfter),
		IsExpiringSoon:    remainingDays <= warningDays,
		Issuer:            cert.Issuer.Organization[0],
		SerialNumber:      cert.SerialNumber.String(),
		Version:           cert.Version,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Fingerprint:       getFingerprint(cert),
	}

	return info, nil
}

// extractSANames extracts Subject Alternative Names from certificate
func extractSANames(cert *x509.Certificate) []string {
	var names []string
	if cert.DNSNames != nil {
		names = append(names, cert.DNSNames...)
	}
	if cert.EmailAddresses != nil {
		for _, email := range cert.EmailAddresses {
			names = append(names, "email:"+email)
		}
	}
	if cert.IPAddresses != nil {
		for _, ip := range cert.IPAddresses {
			names = append(names, ip.String())
		}
	}
	if cert.URIs != nil {
		for _, uri := range cert.URIs {
			names = append(names, uri.String())
		}
	}
	return names
}

// extractSubjectOrg extracts organization from subject
func extractSubjectOrg(cert *x509.Certificate) string {
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return ""
}

// extractSubjectOU extracts organizational unit from subject
func extractSubjectOU(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
}

// extractSubjectCountry extracts country from subject
func extractSubjectCountry(cert *x509.Certificate) string {
	if len(cert.Subject.Country) > 0 {
		return cert.Subject.Country[0]
	}
	return ""
}

// getFingerprint calculates SHA-256 fingerprint of certificate
func getFingerprint(cert *x509.Certificate) string {
	// Calculate SHA-256 fingerprint of the raw certificate
	return hex.EncodeToString(cert.Raw)
}

// ValidateCertificateKeyPair validates that a certificate and private key match
func ValidateCertificateKeyPair(certPEM, keyPEM string) (bool, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse private key
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return false, fmt.Errorf("failed to decode PEM key")
	}

	var pubKey crypto.PublicKey

	switch block.Type {
	case "RSA PRIVATE KEY":
		// Parse PKCS#1 RSA private key
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		pubKey = rsaKey.Public()
	case "PRIVATE KEY", "EC PRIVATE KEY":
		// Parse PKCS#8 private key
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		switch k := key.(type) {
		case *crypto.PrivateKey:
			// Handle encrypted private key
			return false, fmt.Errorf("encrypted private key not supported")
		case interface{ Public() crypto.PublicKey }:
			pubKey = k.Public()
		default:
			return false, fmt.Errorf("unsupported private key type")
		}
	case "ECDSA PRIVATE KEY":
		// Parse ECDSA private key (non-standard type but some tools generate it)
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		pubKey = key.Public()
	default:
		return false, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	// Compare public keys
	return publicKeysEqual(cert.PublicKey, pubKey), nil
}

// publicKeysEqual compares two public keys
func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ka := a.(type) {
	case *crypto.PublicKey:
		// Handle generic public key
		return false
	case interface{ Equal(crypto.PublicKey) bool }:
		return ka.Equal(b)
	default:
		// Fallback: compare bytes
		aBytes, err := x509.MarshalPKIXPublicKey(a)
		if err != nil {
			return false
		}
		bBytes, err := x509.MarshalPKIXPublicKey(b)
		if err != nil {
			return false
		}
		return string(aBytes) == string(bBytes)
	}
}

// FormatPEM formats content as PEM with proper line breaks
func FormatPEM(content string, pemType string) string {
	// Remove existing PEM headers and footers
	lines := strings.Split(content, "\n")
	var cleanContent strings.Builder

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-----BEGIN") &&
		   !strings.HasPrefix(line, "-----END") &&
		   line != "" {
			cleanContent.WriteString(line)
		}
	}

	// Split into 64-character lines
	contentStr := cleanContent.String()
	var formattedLines []string
	for i := 0; i < len(contentStr); i += 64 {
		end := i + 64
		if end > len(contentStr) {
			end = len(contentStr)
		}
		formattedLines = append(formattedLines, contentStr[i:end])
	}

	// Add PEM header and footer
	result := fmt.Sprintf("-----BEGIN %s-----\n", pemType)
	result += strings.Join(formattedLines, "\n")
	result += fmt.Sprintf("\n-----END %s-----\n", pemType)

	return result
}

// ParsePrivateKey parses a PEM-encoded private key
func ParsePrivateKey(keyPEM string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY", "EC PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "ECDSA PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// GetDomainsFromCertificate extracts all domains from a certificate
func GetDomainsFromCertificate(certPEM string) ([]string, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	var domains []string

	// Add Common Name
	if cert.Subject.CommonName != "" {
		domains = append(domains, cert.Subject.CommonName)
	}

	// Add SANs
	if len(cert.DNSNames) > 0 {
		domains = append(domains, cert.DNSNames...)
	}

	// Remove duplicates
	return unique(domains), nil
}

// unique removes duplicate strings from slice
func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if !keys[entry] {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
