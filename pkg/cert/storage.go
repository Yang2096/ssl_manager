package cert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// CertificateStorage handles certificate file operations
type CertificateStorage struct {
	mu      sync.RWMutex
	certDir string
}

// NewCertificateStorage creates a new certificate storage
func NewCertificateStorage(baseDir string) (*CertificateStorage, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &CertificateStorage{
		certDir: baseDir,
	}, nil
}

// SaveCertificate saves a certificate and private key for a domain
func (s *CertificateStorage) SaveCertificate(ctx context.Context, domain, certPEM, keyPEM string) (certPath, keyPath string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	certDir := filepath.Join(s.certDir, "certs", domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create certificate directory: %w", err)
	}

	certPath = filepath.Join(certDir, "fullchain.pem")
	keyPath = filepath.Join(certDir, "privkey.pem")

	// Write certificate
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write private key: %w", err)
	}

	return certPath, keyPath, nil
}

// SaveCSR saves a certificate signing request
func (s *CertificateStorage) SaveCSR(ctx context.Context, domain, csrPEM string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	certDir := filepath.Join(s.certDir, "certs", domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create certificate directory: %w", err)
	}

	csrPath := filepath.Join(certDir, "cert.csr")

	if err := os.WriteFile(csrPath, []byte(csrPEM), 0644); err != nil {
		return "", fmt.Errorf("failed to write CSR: %w", err)
	}

	return csrPath, nil
}

// LoadCertificate loads a certificate for a domain
func (s *CertificateStorage) LoadCertificate(ctx context.Context, domain string) (string, error) {
	certPath := s.GetCertPath(domain)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to load certificate: %w", err)
	}
	return string(certPEM), nil
}

// LoadPrivateKey loads a private key for a domain
func (s *CertificateStorage) LoadPrivateKey(ctx context.Context, domain string) (string, error) {
	keyPath := s.GetKeyPath(domain)
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %w", err)
	}
	return string(keyPEM), nil
}

// LoadBoth loads both certificate and private key for a domain
func (s *CertificateStorage) LoadBoth(ctx context.Context, domain string) (certPEM, keyPEM string, err error) {
	certPath := s.GetCertPath(domain)
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to load certificate: %w", err)
	}

	keyPath := s.GetKeyPath(domain)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to load private key: %w", err)
	}

	return string(certBytes), string(keyBytes), nil
}

// DomainExists checks if a certificate exists for a domain
func (s *CertificateStorage) DomainExists(ctx context.Context, domain string) bool {
	certPath := s.GetCertPath(domain)
	_, err := os.Stat(certPath)
	return err == nil
}

// DeleteDomain removes certificate data for a domain
func (s *CertificateStorage) DeleteDomain(ctx context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	certDir := filepath.Join(s.certDir, "certs", domain)
	return os.RemoveAll(certDir)
}

// ListDomains returns all domains with stored certificates
func (s *CertificateStorage) ListDomains(ctx context.Context) ([]string, error) {
	certsDir := filepath.Join(s.certDir, "certs")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			domains = append(domains, entry.Name())
		}
	}
	return domains, nil
}

// GetCertPath returns the certificate file path for a domain
func (s *CertificateStorage) GetCertPath(domain string) string {
	return filepath.Join(s.certDir, "certs", domain, "fullchain.pem")
}

// GetKeyPath returns the private key file path for a domain
func (s *CertificateStorage) GetKeyPath(domain string) string {
	return filepath.Join(s.certDir, "certs", domain, "privkey.pem")
}

// GetCSRPath returns the CSR file path for a domain
func (s *CertificateStorage) GetCSRPath(domain string) string {
	return filepath.Join(s.certDir, "certs", domain, "cert.csr")
}

// GetBaseDir returns the base directory
func (s *CertificateStorage) GetBaseDir() string {
	return s.certDir
}
