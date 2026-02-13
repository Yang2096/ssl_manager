package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Tencent Cloud credentials
	cfg.TencentSecretID = getEnv("TENCENT_SECRET_ID", "")
	cfg.TencentSecretKey = getEnv("TENCENT_SECRET_KEY", "")
	cfg.TencentRegion = getEnv("TENCENT_REGION", cfg.TencentRegion)

	// ACME settings
	cfg.ACMEAccountEmail = getEnv("ACME_ACCOUNT_EMAIL", cfg.ACMEAccountEmail)
	cfg.ACMEHomeDir = getEnv("ACME_HOME_DIR", cfg.ACMEHomeDir)

	if server := getEnv("ACME_SERVER", ""); server != "" {
		cfg.ACMEServer = server
	}

	cfg.ACMEStaging = getBoolEnv("ACME_STAGING", cfg.ACMEStaging)

	// DNS propagation
	if propagation := getEnv("ACME_DNS_PROPAGATION", ""); propagation != "" {
		if seconds, err := strconv.Atoi(propagation); err == nil {
			cfg.ACMEDNSPropagation = time.Duration(seconds) * time.Second
		}
	}

	// Certificate settings
	if keySize := getEnv("CERT_KEY_SIZE", ""); keySize != "" {
		if size, err := strconv.Atoi(keySize); err == nil {
			cfg.CertKeySize = size
		}
	}

	if warningDays := getEnv("CERT_EXPIRY_WARNING_DAYS", ""); warningDays != "" {
		if days, err := strconv.Atoi(warningDays); err == nil {
			cfg.CertExpiryWarningDays = days
		}
	}

	// Notification settings
	cfg.NotifyEnabled = getBoolEnv("NOTIFY_ENABLED", cfg.NotifyEnabled)
	cfg.NotifyWebhook = getEnv("NOTIFY_WEBHOOK", cfg.NotifyWebhook)

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	var errs []string

	if c.TencentSecretID == "" {
		errs = append(errs, "TENCENT_SECRET_ID is required")
	}
	if c.TencentSecretKey == "" {
		errs = append(errs, "TENCENT_SECRET_KEY is required")
	}
	if c.TencentRegion == "" {
		errs = append(errs, "TENCENT_REGION is required")
	}
	if c.ACMEAccountEmail == "" {
		errs = append(errs, "ACME_ACCOUNT_EMAIL is required")
	}
	if c.ACMEHomeDir == "" {
		errs = append(errs, "ACME_HOME_DIR is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errs, ", "))
	}

	return nil
}

// IsLocal returns true if running in local environment
func (c *Config) IsLocal() bool {
	return !isSCFEnvironment()
}

// isSCFEnvironment checks if running in SCF environment
func isSCFEnvironment() bool {
	// Check for SCF specific environment variables
	return os.Getenv("SCF_RUNTIME") != "" ||
	       os.Getenv("TENCENTCLOUD_RUNENVIRONMENT") == "SCF"
}

// getEnv gets an environment variable or returns the default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getBoolEnv gets a boolean environment variable
func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.ToLower(value) == "true" || value == "1"
	}
	return defaultValue
}

// MustLoad loads configuration and panics on error
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		panic(err)
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}
