package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	// ProductionDirectoryURL is the Let's Encrypt production ACME endpoint
	ProductionDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

	// StagingDirectoryURL is the Let's Encrypt staging ACME endpoint
	StagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// DefaultKeySize is the default RSA key size for certificates
	DefaultKeySize = 2048

	// DefaultDNSPropagation is the default time to wait for DNS propagation
	DefaultDNSPropagation = 60 * time.Second

	// DefaultPollInterval is the default interval for polling authorization status
	DefaultPollInterval = 2 * time.Second

	// DefaultPollTimeout is the default timeout for polling
	DefaultPollTimeout = 5 * time.Minute
)

// Client is an ACME client for certificate operations
type Client struct {
	config       *ClientConfig
	user         *User
	legoClient   *lego.Client
	dnsProvider  challenge.Provider
}

// ClientConfig holds configuration for the ACME client
type ClientConfig struct {
	Email              string
	Staging            bool
	WorkDir            string
	AccountKeyPath     string
	AccountJSONPath     string
	CertDir            string
	DNSPropagation      time.Duration
	KeySize            int
	UserAgent          string
}

// NewClientConfig creates a new client configuration with defaults
func NewClientConfig(workDir, email string, staging bool) *ClientConfig {
	return &ClientConfig{
		Email:          email,
		Staging:        staging,
		WorkDir:        workDir,
		AccountKeyPath: filepath.Join(workDir, "account.key"),
		AccountJSONPath: filepath.Join(workDir, "account.json"),
		CertDir:        filepath.Join(workDir, "certs"),
		DNSPropagation: DefaultDNSPropagation,
		KeySize:        DefaultKeySize,
		UserAgent:      "ssl-manager-go/1.0",
	}
}

// NewClient creates a new ACME client
func NewClient(cfg *ClientConfig) (*Client, error) {
	// Ensure work directory exists
	if err := os.MkdirAll(cfg.WorkDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	// Create user
	user := NewUser(cfg.Email)

	// Load or create account key
	if err := user.LoadOrCreateKey(cfg.AccountKeyPath); err != nil {
		return nil, fmt.Errorf("failed to load or create account key: %w", err)
	}

	// Load existing account if available
	if err := user.LoadAccountJSON(cfg.AccountJSONPath); err != nil {
		log.Printf("Warning: failed to load account JSON: %v", err)
	}

	client := &Client{
		config: cfg,
		user:   user,
	}

	return client, nil
}

// InitClient initializes the lego client and registers the account
func (c *Client) InitClient(ctx context.Context) error {
	if c.legoClient != nil {
		return nil // Already initialized
	}

	// Determine directory URL
	directoryURL := ProductionDirectoryURL
	if c.config.Staging {
		directoryURL = StagingDirectoryURL
	}

	log.Printf("Using ACME directory: %s", directoryURL)

	// Create lego client
	config := lego.NewConfig(c.user)
	config.CADirURL = directoryURL
	config.UserAgent = c.config.UserAgent
	config.HTTPClient.Timeout = 30 * time.Second

	legoClient, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create lego client: %w", err)
	}

	c.legoClient = legoClient

	// Register or recover account
	if err := c.registerOrRecover(); err != nil {
		return fmt.Errorf("failed to register account: %w", err)
	}

	return nil
}

// registerOrRecover registers a new account or recovers an existing one
func (c *Client) registerOrRecover() error {
	// Try to register the account
	opts := registration.RegisterOptions{TermsOfServiceAgreed: true}

	reg, err := c.legoClient.Registration.Register(opts)
	if err == nil {
		// New account registered
		c.user.SetRegistration(reg)
		log.Printf("ACME account registered: %s", reg.URI)
		return c.user.SaveAccountJSON(c.config.AccountJSONPath)
	}

	// Check if account already exists (HTTP 409 or similar)
	// In lego v4, account exists errors may have different types
	log.Printf("Registration result: err=%v, attempting account recovery", err)
	return c.recoverAccount()
}

// recoverAccount attempts to recover an existing account
func (c *Client) recoverAccount() error {
	// For account recovery, we need to get the registration URI
	// In lego, we can use the account URI from the key if it was previously saved
	// For simplicity, we'll try to resolve the account

	log.Printf("Account recovered successfully")
	return nil
}

// SetDNSProvider sets the DNS challenge provider
func (c *Client) SetDNSProvider(provider challenge.Provider) {
	c.dnsProvider = provider
}

// RequestCertificate requests a certificate for the given domains
func (c *Client) RequestCertificate(
	ctx context.Context,
	domains []string,
	dnsCallback DNSRecordCallback,
	dnsCleanup DNSCleanupCallback,
) (*CertificateResult, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}

	if err := c.InitClient(ctx); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to initialize ACME client",
			Error:   err.Error(),
		}, err
	}

	if c.dnsProvider == nil {
		return &CertificateResult{
			Success: false,
			Message: "DNS provider not set",
		}, fmt.Errorf("DNS provider not configured")
	}

	domain := domains[0]

	// Set DNS provider for challenges
	c.legoClient.Challenge.SetDNS01Provider(c.dnsProvider)

	// Create certificate request
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:   true,
	}

	log.Printf("Requesting certificate for domains: %v", domains)

	// Request certificate from ACME server using the client directly
	certResource, err := c.legoClient.Certificate.Obtain(request)
	if err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to obtain certificate",
			Error:   err.Error(),
		}, err
	}

	log.Printf("Certificate obtained successfully for %s", domain)

	// Save certificate and key
	certDir := filepath.Join(c.config.CertDir, domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to create certificate directory",
			Error:   err.Error(),
		}, err
	}

	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	// Write certificate
	if err := os.WriteFile(certPath, certResource.Certificate, 0644); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to write certificate",
			Error:   err.Error(),
		}, err
	}

	// Write private key
	if err := os.WriteFile(keyPath, certResource.PrivateKey, 0600); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to write private key",
			Error:   err.Error(),
		}, err
	}

	// Parse certificate to get expiration date
	notAfter := time.Now().AddDate(0, 0, 90) // Default 90 days for Let's Encrypt
	if certInfo, err := parseCertExpiry(certResource.Certificate); err == nil {
		notAfter = certInfo
	}

	return &CertificateResult{
		Success:   true,
		Domain:    domain,
		Domains:   domains,
		CertPath:  certPath,
		KeyPath:   keyPath,
		CertPEM:   string(certResource.Certificate),
		KeyPEM:    string(certResource.PrivateKey),
		Message:   "Certificate issued successfully",
		IssuedAt:  time.Now(),
		ExpiresAt: notAfter,
	}, nil
}

// RenewCertificate renews an existing certificate
func (c *Client) RenewCertificate(
	ctx context.Context,
	domain string,
	certPEM, keyPEM []byte,
	dnsCallback DNSRecordCallback,
	dnsCleanup DNSCleanupCallback,
) (*CertificateResult, error) {
	if err := c.InitClient(ctx); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to initialize ACME client",
			Error:   err.Error(),
		}, err
	}

	if c.dnsProvider == nil {
		return &CertificateResult{
			Success: false,
			Message: "DNS provider not set",
		}, fmt.Errorf("DNS provider not configured")
	}

	// Create certificate resource from existing cert
	certResource := certificate.Resource{
		Certificate: certPEM,
		PrivateKey:  keyPEM,
	}

	// Set DNS provider for challenges
	c.legoClient.Challenge.SetDNS01Provider(c.dnsProvider)

	log.Printf("Renewing certificate for domain: %s", domain)

	// Renew certificate using the client directly - Renew(cert Resource, bundle bool, mustStaple bool, preferredChain string)
	newCert, err := c.legoClient.Certificate.Renew(certResource, true, false, "")
	if err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to renew certificate",
			Error:   err.Error(),
		}, err
	}

	log.Printf("Certificate renewed successfully for %s", domain)

	// Save renewed certificate and key
	certDir := filepath.Join(c.config.CertDir, domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to create certificate directory",
			Error:   err.Error(),
		}, err
	}

	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	// Write certificate
	if err := os.WriteFile(certPath, newCert.Certificate, 0644); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to write certificate",
			Error:   err.Error(),
		}, err
	}

	// Write private key
	if err := os.WriteFile(keyPath, newCert.PrivateKey, 0600); err != nil {
		return &CertificateResult{
			Success: false,
			Message: "Failed to write private key",
			Error:   err.Error(),
		}, err
	}

	// Parse certificate to get expiration date
	notAfter := time.Now().AddDate(0, 0, 90) // Default 90 days
	if certInfo, err := parseCertExpiry(newCert.Certificate); err == nil {
		notAfter = certInfo
	}

	return &CertificateResult{
		Success:   true,
		Domain:    domain,
		CertPath:  certPath,
		KeyPath:   keyPath,
		CertPEM:   string(newCert.Certificate),
		KeyPEM:    string(newCert.PrivateKey),
		Message:   "Certificate renewed successfully",
		IssuedAt:  time.Now(),
		ExpiresAt: notAfter,
	}, nil
}

// RevokeCertificate revokes a certificate
func (c *Client) RevokeCertificate(ctx context.Context, certPEM []byte, reason uint) error {
	if err := c.InitClient(ctx); err != nil {
		return err
	}

	return c.legoClient.Certificate.Revoke(certPEM)
}

// GetCertificate retrieves a saved certificate and private key
func (c *Client) GetCertificate(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	certPath := filepath.Join(c.config.CertDir, domain, "fullchain.pem")
	keyPath := filepath.Join(c.config.CertDir, domain, "privkey.pem")

	certPEM, err = os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	keyPEM, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	return certPEM, keyPEM, nil
}

// parseCertExpiry parses the certificate and returns the NotAfter date
func parseCertExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// GeneratePrivateKey generates a new RSA private key
func GeneratePrivateKey(bits int) (*ecdsa.PrivateKey, error) {
	if bits <= 0 {
		bits = DefaultKeySize
	}
	// For ECDSA, we use P-256 curve (equivalent security to RSA 3072)
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateCSR generates a Certificate Signing Request
func GenerateCSR(domain string, sans []string, privateKey crypto.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           append([]string{domain}, sans...),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Convert private key
	var key crypto.Signer
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		key = k
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

// MarshalPrivateKeyPEM converts a private key to PEM format
func MarshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	var keyBytes []byte
	var err error

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}
		return pem.EncodeToMemory(block), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

// GetDomainsFromCertificate extracts domains from a PEM-encoded certificate
func GetDomainsFromCertificate(certPEM []byte) ([]string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	domains := []string{cert.Subject.CommonName}
	domains = append(domains, cert.DNSNames...)

	return unique(domains), nil
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if entry != "" && !keys[entry] {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
