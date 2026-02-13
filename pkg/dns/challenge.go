package dns

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/yang/ssl-manager/pkg/domain"
)

// ChallengeHandler handles DNS challenges for ACME
type ChallengeHandler struct {
	provider       Provider
	addedRecords   map[string]*ChallengeRecord
	mu             sync.Mutex
	dnsPropagation time.Duration
}

// ChallengeRecord represents a DNS challenge record
type ChallengeRecord struct {
	RecordName  string `json:"record_name"`
	RecordValue string `json:"record_value"`
	Domain      string `json:"domain"`
	SubDomain   string `json:"sub_domain"`
	RecordID    string `json:"record_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewChallengeHandler creates a new DNS challenge handler
func NewChallengeHandler(provider Provider, dnsPropagation time.Duration) *ChallengeHandler {
	return &ChallengeHandler{
		provider:      provider,
		addedRecords:  make(map[string]*ChallengeRecord),
		dnsPropagation: dnsPropagation,
	}
}

// AddValidationRecord adds a DNS validation record
func (h *ChallengeHandler) AddValidationRecord(ctx context.Context, recordName, recordValue string, ttl int) (*ChallengeRecord, error) {
	log.Printf("Adding DNS validation record: %s = %s", recordName, recordValue)

	// Parse the record name to extract main domain and subdomain
	mainDomain, subDomain, err := h.extractDomain(recordName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract domain: %w", err)
	}

	log.Printf("Parsed: main_domain=%s, sub_domain=%s", mainDomain, subDomain)

	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if record already exists
	key := recordName + ":" + recordValue
	if existing, ok := h.addedRecords[key]; ok {
		log.Printf("DNS record already tracked: %s", existing.RecordID)
		return existing, nil
	}

	// Check if record exists in DNS
	existingRecords, err := h.provider.GetTXTRecords(ctx, mainDomain, subDomain)
	if err == nil {
		for _, record := range existingRecords {
			if record.Value == recordValue {
				log.Printf("DNS record already exists: %s", record.ID)
				challengeRecord := &ChallengeRecord{
					RecordName:  recordName,
					RecordValue: recordValue,
					Domain:      mainDomain,
					SubDomain:   subDomain,
					RecordID:    record.ID,
					CreatedAt:   time.Now(),
				}
				h.addedRecords[key] = challengeRecord
				return challengeRecord, nil
			}
		}
	}

	// Add new record
	recordID, err := h.provider.AddTXTRecord(ctx, mainDomain, subDomain, recordValue, ttl)
	if err != nil {
		return nil, fmt.Errorf("failed to add DNS record: %w", err)
	}

	challengeRecord := &ChallengeRecord{
		RecordName:  recordName,
		RecordValue: recordValue,
		Domain:      mainDomain,
		SubDomain:   subDomain,
		RecordID:    recordID,
		CreatedAt:   time.Now(),
	}

	h.addedRecords[key] = challengeRecord
	log.Printf("DNS record added with ID: %s", recordID)

	return challengeRecord, nil
}

// CleanupRecord removes a DNS validation record
func (h *ChallengeHandler) CleanupRecord(ctx context.Context, record *ChallengeRecord) error {
	if record == nil {
		return fmt.Errorf("nil record")
	}

	if record.RecordID == "" {
		log.Printf("Cannot cleanup record without ID: %s", record.RecordName)
		return nil
	}

	log.Printf("Deleting DNS record: %s (ID: %s)", record.RecordName, record.RecordID)

	err := h.provider.DeleteTXTRecord(ctx, record.Domain, record.RecordID)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %w", err)
	}

	// Remove from tracking
	h.mu.Lock()
	key := record.RecordName + ":" + record.RecordValue
	delete(h.addedRecords, key)
	h.mu.Unlock()

	log.Printf("DNS record deleted: %s", record.RecordID)
	return nil
}

// CleanupRecords removes all added DNS records
func (h *ChallengeHandler) CleanupRecords(ctx context.Context) error {
	h.mu.Lock()
	records := make([]*ChallengeRecord, 0, len(h.addedRecords))
	for _, record := range h.addedRecords {
		records = append(records, record)
	}
	h.mu.Unlock()

	var errs []string
	for _, record := range records {
		if err := h.CleanupRecord(ctx, record); err != nil {
			log.Printf("Failed to cleanup record %s: %v", record.RecordName, err)
			errs = append(errs, fmt.Sprintf("%s: %v", record.RecordName, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// GetRecordByName returns a tracked record by name
func (h *ChallengeHandler) GetRecordByName(recordName string) *ChallengeRecord {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, record := range h.addedRecords {
		if record.RecordName == recordName {
			return record
		}
	}
	return nil
}

// GetAddedRecords returns all tracked records
func (h *ChallengeHandler) GetAddedRecords() []*ChallengeRecord {
	h.mu.Lock()
	defer h.mu.Unlock()

	records := make([]*ChallengeRecord, 0, len(h.addedRecords))
	for _, record := range h.addedRecords {
		records = append(records, record)
	}
	return records
}

// extractDomain extracts main domain and subdomain from a full domain
func (h *ChallengeHandler) extractDomain(fullDomain string) (string, string, error) {
	// Remove _acme-challenge prefix if present
	domainPart := fullDomain
	if strings.HasPrefix(fullDomain, "_acme-challenge.") {
		domainPart = strings.TrimPrefix(fullDomain, "_acme-challenge.")
	}

	// Parse domain
	parsed, err := domain.ParseDomain(domainPart)
	if err != nil {
		return "", "", err
	}

	mainDomain := parsed.MainDomain
	subDomain := parsed.SubDomain

	// If the original started with _acme-challenge, we need to prefix it
	if strings.HasPrefix(fullDomain, "_acme-challenge.") {
		if subDomain == "@" {
			subDomain = "_acme-challenge"
		} else {
			subDomain = "_acme-challenge." + subDomain
		}
	}

	return mainDomain, subDomain, nil
}

// SetProvider sets the DNS provider
func (h *ChallengeHandler) SetProvider(provider Provider) {
	h.provider = provider
}

// GetProvider returns the DNS provider
func (h *ChallengeHandler) GetProvider() Provider {
	return h.provider
}

// RecordCount returns the number of tracked records
func (h *ChallengeHandler) RecordCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.addedRecords)
}
