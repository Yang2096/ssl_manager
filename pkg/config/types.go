package config

import "time"

// Config holds the application configuration
type Config struct {
	// Tencent Cloud API credentials
	TencentSecretID  string
	TencentSecretKey string
	TencentRegion    string

	// ACME settings
	ACMEServer         string
	ACMEStaging        bool
	ACMEHomeDir        string
	ACMEAccountEmail   string
	ACMEDNSPropagation time.Duration
	ACMEDNSResolvers   []string        // Custom DNS resolvers (e.g., "8.8.8.8:53,1.1.1.1:53")
	ACMEDNSTimeout     time.Duration  // DNS query timeout (default: 10 seconds)

	// Certificate settings
	CertKeySize             int
	CertExpiryWarningDays   int

	// Notification settings
	NotifyEnabled bool
	NotifyWebhook string

	// Qiniu settings (optional - for certificate sync to Qiniu CDN)
	QiniuAccessKey string
	QiniuSecretKey string
}

// AcmeConfig holds ACME-specific path configurations
type AcmeConfig struct {
	HomeDir         string
	AccountKeyPath  string
	AccountFilePath string
	CertDir         string
	FullchainPath   string
	PrivkeyPath     string
	DNSPropagation  time.Duration
	DNSPollInterval time.Duration
	DNSPollTimeout  time.Duration
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		TencentRegion:         "ap-guangzhou",
		ACMEServer:           "https://acme-v02.api.letsencrypt.org/directory",
		ACMEStaging:          false,
		ACMEHomeDir:          "/tmp/acme",
		ACMEAccountEmail:     "admin@example.com",
		ACMEDNSPropagation:   60 * time.Second,
		ACMEDNSTimeout:       10 * time.Second,
		CertKeySize:          2048,
		CertExpiryWarningDays: 30,
		NotifyEnabled:        false,
	}
}

// DefaultAcmeConfig returns ACME configuration based on home directory
func DefaultAcmeConfig(homeDir string) *AcmeConfig {
	return &AcmeConfig{
		HomeDir:         homeDir,
		AccountKeyPath:  homeDir + "/account.key",
		AccountFilePath: homeDir + "/account.json",
		CertDir:         "",  // Will be set per domain
		FullchainPath:   "",  // Will be set per domain
		PrivkeyPath:     "",  // Will be set per domain
		DNSPropagation:  60 * time.Second,
		DNSPollInterval: 2 * time.Second,
		DNSPollTimeout:  5 * time.Minute,
	}
}

// GetAcmeConfig returns ACME configuration for a specific domain
func (c *Config) GetAcmeConfig(domain string) *AcmeConfig {
	acmeCfg := DefaultAcmeConfig(c.ACMEHomeDir)
	acmeCfg.DNSPropagation = c.ACMEDNSPropagation
	acmeCfg.CertDir = c.ACMEHomeDir + "/certs/" + domain
	acmeCfg.FullchainPath = acmeCfg.CertDir + "/fullchain.pem"
	acmeCfg.PrivkeyPath = acmeCfg.CertDir + "/privkey.pem"
	return acmeCfg
}

// IsStaging returns true if using staging environment
func (c *Config) IsStaging() bool {
	return c.ACMEStaging
}

// GetServerURL returns the ACME server URL based on staging setting
func (c *Config) GetServerURL() string {
	if c.ACMEStaging {
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return c.ACMEServer
}
