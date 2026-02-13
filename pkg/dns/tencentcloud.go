package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"

	domainpkg "github.com/yang/ssl-manager/pkg/domain"
)

// TencentCloudProvider implements DNS provider using Tencent Cloud DNSPod API
type TencentCloudProvider struct {
	client             *dnspod.Client
	secretID           string
	secretKey          string
	region             string
	httpClient         *http.Client
	propagationTimeout time.Duration
	pollingInterval    time.Duration
}

// NewTencentCloudProvider creates a new Tencent Cloud DNS provider
func NewTencentCloudProvider(secretID, secretKey, region string, propagationTimeout time.Duration) (*TencentCloudProvider, error) {
	credential := common.NewCredential(secretID, secretKey)

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"

	client, err := dnspod.NewClient(credential, region, cpf)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNSPod client: %w", err)
	}

	return &TencentCloudProvider{
		client:             client,
		secretID:           secretID,
		secretKey:          secretKey,
		region:             region,
		propagationTimeout: propagationTimeout,
		pollingInterval:    3 * time.Second,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// AddTXTRecord adds a TXT record to DNSPod
func (p *TencentCloudProvider) AddTXTRecord(ctx context.Context, domain, subDomain, value string, ttl int) (string, error) {
	log.Printf("Adding TXT record: %s.%s = %s", subDomain, domain, value)

	// Set default TTL
	if ttl <= 0 {
		ttl = 600
	}

	// Check if record already exists
	existingRecords, err := p.GetTXTRecords(ctx, domain, subDomain)
	if err == nil {
		for _, record := range existingRecords {
			if record.Value == value {
				log.Printf("TXT record already exists: %s", record.ID)
				return record.ID, nil
			}
		}
	}

	// Create new record request
	request := dnspod.NewCreateRecordRequest()
	request.Domain = common.StringPtr(domain)
	request.SubDomain = common.StringPtr(subDomain)
	request.RecordType = common.StringPtr("TXT")
	request.RecordLine = common.StringPtr("默认")
	request.Value = common.StringPtr(value)
	request.TTL = common.Uint64Ptr(uint64(ttl))

	response, err := p.client.CreateRecord(request)
	if err != nil {
		return "", fmt.Errorf("failed to create TXT record: %w", err)
	}

	recordID := ""
	if response.Response.RecordId != nil {
		recordID = strconv.FormatUint(*response.Response.RecordId, 10)
		log.Printf("TXT record added with ID: %s", recordID)
	}

	return recordID, nil
}

// DeleteTXTRecord deletes a TXT record from DNSPod
func (p *TencentCloudProvider) DeleteTXTRecord(ctx context.Context, domain string, recordID string) error {
	log.Printf("Deleting TXT record: %s (ID: %s)", domain, recordID)

	// Parse record ID to uint64
	id, err := strconv.ParseUint(recordID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid record ID: %w", err)
	}

	request := dnspod.NewDeleteRecordRequest()
	request.Domain = common.StringPtr(domain)
	request.RecordId = common.Uint64Ptr(id)

	_, err = p.client.DeleteRecord(request)
	if err != nil {
		// Check if it's a "not found" error
		if sdkErr, ok := err.(*errors.TencentCloudSDKError); ok {
			if sdkErr.Code == "ResourceNotFound.NoDataOfRecord" || sdkErr.Code == "InvalidParameter.RecordIdError" {
				log.Printf("Record %s not found, assuming already deleted", recordID)
				return nil
			}
		}
		return fmt.Errorf("failed to delete TXT record: %w", err)
	}

	log.Printf("TXT record deleted: %s", recordID)
	return nil
}

// GetTXTRecords retrieves TXT records for a domain
func (p *TencentCloudProvider) GetTXTRecords(ctx context.Context, domain, subDomain string) ([]TXTRecord, error) {
	request := dnspod.NewDescribeRecordListRequest()
	request.Domain = common.StringPtr(domain)
	if subDomain != "" && subDomain != "@" {
		request.Subdomain = common.StringPtr(subDomain)
	}

	response, err := p.client.DescribeRecordList(request)
	if err != nil {
		// Handle empty result
		if sdkErr, ok := err.(*errors.TencentCloudSDKError); ok {
			if sdkErr.Code == "ResourceNotFound.NoDataOfRecord" {
				return []TXTRecord{}, nil
			}
		}
		return nil, fmt.Errorf("failed to get TXT records: %w", err)
	}

	records := make([]TXTRecord, 0)
	if response.Response.RecordList == nil {
		return records, nil
	}

	for _, record := range response.Response.RecordList {
		if record.Type != nil && *record.Type != "TXT" {
			continue
		}

		var recordID, name, value, recordType, status string
		var ttl int
		var updatedOn time.Time

		if record.RecordId != nil {
			recordID = strconv.FormatUint(*record.RecordId, 10)
		}
		if record.Name != nil {
			name = *record.Name
		}
		if record.Value != nil {
			value = *record.Value
		}
		if record.Type != nil {
			recordType = *record.Type
		}
		if record.TTL != nil {
			ttl = int(*record.TTL)
		}
		if record.Status != nil {
			status = *record.Status
		}
		if record.UpdatedOn != nil {
			updatedOn, _ = time.Parse("2006-01-02 15:04:05", *record.UpdatedOn)
		}

		records = append(records, TXTRecord{
			ID:        recordID,
			Name:      name,
			Value:     value,
			Type:      recordType,
			TTL:       ttl,
			Status:    status,
			UpdatedOn: updatedOn,
		})
	}

	return records, nil
}

// GetName returns the provider name
func (p *TencentCloudProvider) GetName() string {
	return "tencentcloud"
}

// ModifyTXTRecord modifies an existing TXT record
func (p *TencentCloudProvider) ModifyTXTRecord(ctx context.Context, domain, subDomain, value, recordID string, ttl int) error {
	log.Printf("Modifying TXT record: %s (ID: %s)", recordID, value)

	if ttl <= 0 {
		ttl = 600
	}

	// Parse record ID to uint64
	id, err := strconv.ParseUint(recordID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid record ID: %w", err)
	}

	request := dnspod.NewModifyRecordRequest()
	request.Domain = common.StringPtr(domain)
	request.SubDomain = common.StringPtr(subDomain)
	request.RecordType = common.StringPtr("TXT")
	request.RecordLine = common.StringPtr("默认")
	request.Value = common.StringPtr(value)
	request.TTL = common.Uint64Ptr(uint64(ttl))
	request.RecordId = common.Uint64Ptr(id)

	_, err = p.client.ModifyRecord(request)
	if err != nil {
		return fmt.Errorf("failed to modify TXT record: %w", err)
	}

	log.Printf("TXT record modified: %s", recordID)
	return nil
}

// RecordInfo holds information about a DNS record
type RecordInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Type      string `json:"type"`
	TTL       int    `json:"ttl"`
	Status    string `json:"status"`
	UpdatedOn string `json:"updated_on"`
}

// ToJSON converts a TXTRecord to JSON
func (r TXTRecord) ToJSON() string {
	data, _ := json.Marshal(r)
	return string(data)
}

// Present implements challenge.Provider interface
// Presents the ACME challenge DNS record
func (p *TencentCloudProvider) Present(domain, token, keyAuth string) error {
	// Use correct domain parsing logic
	parsed, err := domainpkg.ParseDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to parse domain %s: %w", domain, err)
	}

	baseDomain := parsed.MainDomain
	var subDomain string
	if parsed.SubDomain == "@" {
		subDomain = "_acme-challenge"
	} else {
		subDomain = "_acme-challenge." + parsed.SubDomain
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)

	_, err = p.AddTXTRecord(context.Background(), baseDomain, subDomain, info.Value, 600)
	return err
}

// CleanUp implements challenge.Provider interface
// Removes the ACME challenge DNS record
func (p *TencentCloudProvider) CleanUp(domain, token, keyAuth string) error {
	// Use correct domain parsing logic
	parsed, err := domainpkg.ParseDomain(domain)
	if err != nil {
		return fmt.Errorf("failed to parse domain %s: %w", domain, err)
	}

	baseDomain := parsed.MainDomain
	var subDomain string
	if parsed.SubDomain == "@" {
		subDomain = "_acme-challenge"
	} else {
		subDomain = "_acme-challenge." + parsed.SubDomain
	}

	// Get existing records to find the one to delete
	records, err := p.GetTXTRecords(context.Background(), baseDomain, subDomain)
	if err != nil {
		return err
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)

	for _, record := range records {
		if record.Value == info.Value {
			return p.DeleteTXTRecord(context.Background(), baseDomain, record.ID)
		}
	}

	return nil
}

// Timeout implements challenge.ProviderTimeout interface
// Returns the timeout and polling interval for DNS propagation
func (p *TencentCloudProvider) Timeout() (time.Duration, time.Duration) {
	if p.propagationTimeout > 0 {
		return p.propagationTimeout, p.pollingInterval
	}
	// Default values: 60 seconds timeout, 5 seconds interval
	return 60 * time.Second, 3 * time.Second
}
