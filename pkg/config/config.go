package config

import (
	"fmt"
	"log"
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
			log.Printf("got ACMEDNSPropagation : %d", seconds)
			cfg.ACMEDNSPropagation = time.Duration(seconds) * time.Second
		}
	}

	// DNS resolvers configuration (comma-separated list)
	if resolvers := getEnv("ACME_DNS_RESOLVERS", ""); resolvers != "" {
		servers := strings.Split(resolvers, ",")
		for _, server := range servers {
			server = strings.TrimSpace(server)
			if server != "" {
				cfg.ACMEDNSResolvers = append(cfg.ACMEDNSResolvers, server)
			}
		}
		if len(cfg.ACMEDNSResolvers) > 0 {
			log.Printf("Configured custom DNS resolvers: %v", cfg.ACMEDNSResolvers)
		}
	}

	// DNS query timeout in seconds (optional, defaults to 10)
	if timeout := getEnv("ACME_DNS_TIMEOUT", ""); timeout != "" {
		if seconds, err := strconv.Atoi(timeout); err == nil && seconds > 0 {
			cfg.ACMEDNSTimeout = time.Duration(seconds) * time.Second
			log.Printf("Configured DNS timeout: %d seconds", seconds)
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

	// Qiniu settings (optional)
	cfg.QiniuAccessKey = getEnv("QINIU_ACCESS_KEY", "")
	cfg.QiniuSecretKey = getEnv("QINIU_SECRET_KEY", "")
	if cfg.QiniuAccessKey != "" && cfg.QiniuSecretKey != "" {
		log.Printf("Qiniu integration enabled")
	}

	// Deployment polling settings
	if interval := getEnv("DEPLOY_POLL_INITIAL_INTERVAL", ""); interval != "" {
		if seconds, err := strconv.Atoi(interval); err == nil && seconds > 0 {
			cfg.DeployPollInitialInterval = time.Duration(seconds) * time.Second
		}
	}
	if interval := getEnv("DEPLOY_POLL_PROGRESS_INTERVAL", ""); interval != "" {
		if seconds, err := strconv.Atoi(interval); err == nil && seconds > 0 {
			cfg.DeployPollProgressInterval = time.Duration(seconds) * time.Second
		}
	}
	if timeout := getEnv("DEPLOY_POLL_TIMEOUT", ""); timeout != "" {
		if seconds, err := strconv.Atoi(timeout); err == nil && seconds > 0 {
			cfg.DeployPollTimeout = time.Duration(seconds) * time.Second
		}
	}

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

// domainToEnvKey converts a domain to environment variable key format
// example.com -> EXAMPLE_COM
// api.sub.example.com -> API_SUB_EXAMPLE_COM
// *.example.com -> _EXAMPLE_COM (wildcard)
func domainToEnvKey(domain string) string {
	// Handle wildcard domains
	domain = strings.TrimPrefix(domain, "*.")

	// Replace dots with underscores and convert to uppercase
	return strings.ToUpper(strings.ReplaceAll(domain, ".", "_"))
}

// GetUpdateConfigForDomain gets resource update configuration for a specific domain
// Only returns configuration if SSL_UPDATE_CONFIG_{DOMAIN} is explicitly set
// Returns nil if no domain-specific configuration is found
func (c *Config) GetUpdateConfigForDomain(domain string) []ResourceUpdateConfig {
	envKey := "SSL_UPDATE_CONFIG_" + domainToEnvKey(domain)

	// Only check domain-specific configuration, no fallback
	if configs := c.loadUpdateConfigFromEnv(envKey); len(configs) > 0 {
		log.Printf("Using domain-specific update config for %s from %s", domain, envKey)
		return configs
	}

	// No explicit configuration found
	log.Printf("No explicit update config found for %s", domain)
	return nil
}

// loadUpdateConfigFromEnv loads resource update config from an environment variable
func (c *Config) loadUpdateConfigFromEnv(envKey string) []ResourceUpdateConfig {
	jsonStr := os.Getenv(envKey)
	if jsonStr == "" {
		return nil
	}

	configs, err := ParseResourceUpdateConfigs(jsonStr)
	if err != nil {
		log.Printf("Warning: Failed to parse %s: %v", envKey, err)
		return nil
	}

	return configs
}

