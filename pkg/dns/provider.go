package dns

import (
	"context"
	"time"
)

// Provider is the interface for DNS providers
type Provider interface {
	// AddTXTRecord adds a TXT record
	AddTXTRecord(ctx context.Context, domain, subDomain, value string, ttl int) (string, error)

	// DeleteTXTRecord deletes a TXT record by ID
	DeleteTXTRecord(ctx context.Context, domain string, recordID string) error

	// GetTXTRecords retrieves TXT records for a domain
	GetTXTRecords(ctx context.Context, domain, subDomain string) ([]TXTRecord, error)

	// GetName returns the provider name
	GetName() string
}

// TXTRecord represents a DNS TXT record
type TXTRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	Type      string    `json:"type"`
	TTL       int       `json:"ttl"`
	Status    string    `json:"status"`
	UpdatedOn time.Time `json:"updated_on"`
}

// ProviderConfig holds configuration for DNS providers
type ProviderConfig struct {
	SecretID  string
	SecretKey  string
	Region     string
	Timeout    time.Duration
}

// DefaultProviderConfig returns a default provider configuration
func DefaultProviderConfig() *ProviderConfig {
	return &ProviderConfig{
		Region:  "ap-guangzhou",
		Timeout: 30 * time.Second,
	}
}

// NewProviderConfig creates a new provider configuration with credentials
func NewProviderConfig(secretID, secretKey, region string) *ProviderConfig {
	return &ProviderConfig{
		SecretID: secretID,
		SecretKey: secretKey,
		Region:    region,
		Timeout:   30 * time.Second,
	}
}
