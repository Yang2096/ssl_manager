package ssl

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// Client wraps the Tencent Cloud SSL client
type Client struct {
	client   *ssl.Client
	secretID  string
	secretKey string
	region    string
}

// Supported resource types for certificate deployment
var ResourceTypes = []string{
	"clb",      // Cloud Load Balancer
	"cdn",      // Content Delivery Network
	"waf",      // Web Application Firewall
	"live",     // Live Streaming
	"ddos",     // DDoS Protection
	"teo",      // EdgeOne
	"apigateway", // API Gateway
	"vod",      // Video on Demand
	"tke",      // Kubernetes Engine
	"tcb",      // CloudBase
	"tse",      // Microservice Engine
	"cos",      // Object Storage
	"scf",      // Serverless Cloud Function
}

// NewClient creates a new SSL client
func NewClient(secretID, secretKey, region string) (*Client, error) {
	credential := common.NewCredential(secretID, secretKey)

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, err := ssl.NewClient(credential, region, cpf)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSL client: %w", err)
	}

	return &Client{
		client:   client,
		secretID: secretID,
		secretKey: secretKey,
		region:    region,
	}, nil
}

// UploadCertificate uploads a certificate to Tencent Cloud SSL service
func (c *Client) UploadCertificate(ctx context.Context, certPEM, keyPEM string) (string, error) {
	log.Printf("Uploading certificate to SSL service")

	request := ssl.NewUploadCertificateRequest()
	request.CertificatePublicKey = common.StringPtr(certPEM)
	request.CertificatePrivateKey = common.StringPtr(keyPEM)

	response, err := c.client.UploadCertificate(request)
	if err != nil {
		return "", fmt.Errorf("failed to upload certificate: %w", err)
	}

	certID := ""
	if response.Response.CertificateId != nil {
		certID = *response.Response.CertificateId
		log.Printf("Certificate uploaded with ID: %s", certID)
	}

	return certID, nil
}

// GetCertificateList retrieves certificates from Tencent Cloud SSL service
func (c *Client) GetCertificateList(ctx context.Context, limit, offset int, searchKey string) ([]CertificateInfo, error) {
	request := ssl.NewDescribeCertificatesRequest()
	request.Limit = common.Uint64Ptr(uint64(limit))
	request.Offset = common.Uint64Ptr(uint64(offset))
	if searchKey != "" {
		request.SearchKey = common.StringPtr(searchKey)
	}

	response, err := c.client.DescribeCertificates(request)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate list: %w", err)
	}

	certificates := make([]CertificateInfo, 0)
	if response.Response.Certificates != nil {
		for _, cert := range response.Response.Certificates {
			certificates = append(certificates, *sdkCertToCertificateInfo(cert))
		}
	}

	return certificates, nil
}

// formatStatus converts status uint64 to readable string
func formatStatus(status *uint64) string {
	if status == nil {
		return ""
	}
	switch *status {
	case 0:
		return "pending"
	case 1:
		return "issued"
	case 2:
		return "failed"
	case 3:
		return "expired"
	case 4:
		return "revoked"
	default:
		return fmt.Sprintf("unknown(%d)", *status)
	}
}

// sdkCertToCertificateInfo converts SDK Certificates to CertificateInfo
func sdkCertToCertificateInfo(cert *ssl.Certificates) *CertificateInfo {
	return &CertificateInfo{
		CertificateID:  getString(cert.CertificateId),
		Domain:         getString(cert.Domain),
		Alias:          getString(cert.Alias),
		Status:         formatStatus(cert.Status),
		StatusName:     getString(cert.StatusName),
		CertBeginTime:  getString(cert.CertBeginTime),
		CertEndTime:    getString(cert.CertEndTime),
		IsVip:         getBool(cert.IsVip),
		IsWildcard:     getBool(cert.IsWildcard),
		IsDv:          getBool(cert.IsDv),
	}
}

// GetCertificateByDomain searches for a certificate by domain
func (c *Client) GetCertificateByDomain(ctx context.Context, domain string) (*CertificateInfo, error) {
	certificates, err := c.GetCertificateList(ctx, 100, 0, domain)
	if err != nil {
		return nil, err
	}

	for i := range certificates {
		cert := &certificates[i]
		// Check if domain matches in Domain field
		if cert.Domain == domain || containsDomain(cert.Domain, domain) {
			return cert, nil
		}
	}

	return nil, nil
}

// GetCertificateID retrieves a certificate ID by domain
func (c *Client) GetCertificateID(ctx context.Context, domain string) (string, error) {
	cert, err := c.GetCertificateByDomain(ctx, domain)
	if err != nil {
		return "", err
	}
	if cert == nil {
		return "", nil
	}

	return cert.CertificateID, nil
}

// DeleteCertificate deletes a certificate from Tencent Cloud SSL service
func (c *Client) DeleteCertificate(ctx context.Context, certID string) error {
	log.Printf("Deleting certificate: %s", certID)

	request := ssl.NewDeleteCertificateRequest()
	request.CertificateId = common.StringPtr(certID)

	_, err := c.client.DeleteCertificate(request)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	log.Printf("Certificate deleted: %s", certID)
	return nil
}

// CheckCertificateStatus retrieves detailed status of a certificate
func (c *Client) CheckCertificateStatus(ctx context.Context, certID string) (*CertificateInfo, error) {
	request := ssl.NewDescribeCertificateDetailRequest()
	request.CertificateId = common.StringPtr(certID)

	response, err := c.client.DescribeCertificateDetail(request)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate detail: %w", err)
	}

	// Return complete certificate information
	return &CertificateInfo{
		CertificateID:  getString(response.Response.CertificateId),
		Domain:         getString(response.Response.Domain),
		Status:         formatStatus(response.Response.Status),
		StatusMsg:      getString(response.Response.StatusMsg),
		CertBeginTime:  getString(response.Response.CertBeginTime),
		CertEndTime:    getString(response.Response.CertEndTime),
		CommonName:     "", // Not available in Go SDK response
		SubjectAltName:  getStringPtrSlice(response.Response.SubjectAltName),
		Issuer:         "", // Not available in Go SDK response
		ValidityPeriod:  getString(response.Response.ValidityPeriod),
	}, nil
}

// UpdateResult represents the result of certificate update operation
type UpdateResult struct {
	CertificateID  string `json:"certificate_id"`  // Preserved certificate ID
	DeployRecordID string `json:"deploy_record_id"` // Async task ID
	Status        string `json:"status"`         // success, pending, failed
	Message       string `json:"message"`
	IsPolling     bool   `json:"is_polling"`      // True if polling was required
}

// Update configuration constants
const (
	DefaultUpdatePollInterval = 5  // seconds
	DefaultUpdatePollTimeout  = 120 // seconds (2 minutes)
)

// pollUpdateStatus polls the certificate update status until completion
func (c *Client) pollUpdateStatus(ctx context.Context, certID string) (*UpdateResult, error) {
	log.Printf("Polling update status for certificate: %s", certID)

	ticker := time.NewTicker(DefaultUpdatePollInterval * time.Second)
	defer ticker.Stop()

	timeout := time.After(DefaultUpdatePollTimeout * time.Second)
	pollCount := 0
	maxPolls := DefaultUpdatePollTimeout / DefaultUpdatePollInterval

	for pollCount < maxPolls {
		select {
		case <-ticker.C:
			pollCount++
			log.Printf("Polling attempt %d/%d", pollCount, maxPolls)

			// Check certificate detail to verify update
			cert, err := c.CheckCertificateStatus(ctx, certID)
			if err != nil {
				log.Printf("Failed to check certificate status: %v", err)
				continue
			}

			// Check if certificate has been updated (verify by checking end time)
			if cert.CertEndTime != "" {
				// Parse the end time to check if it's recent (within last 5 minutes)
				endTime, err := time.Parse("2006-01-02 15:04:05", cert.CertEndTime)
				if err == nil {
					timeSinceUpdate := time.Since(endTime)
					// If end time is in the future and recent, update was successful
					if timeSinceUpdate < 5*time.Minute && endTime.After(time.Now().Add(-24*time.Hour)) {
						log.Printf("Certificate update verified: new end time %s", cert.CertEndTime)
						return &UpdateResult{
							CertificateID: certID,
							Status:       "success",
							Message:      "Certificate updated successfully",
							IsPolling:    true,
						}, nil
					}
				}
			}

		case <-timeout:
			return &UpdateResult{
				CertificateID: certID,
				Status:       "pending",
				Message:      fmt.Sprintf("Update polling timeout after %ds", DefaultUpdatePollTimeout),
				IsPolling:    true,
			}, fmt.Errorf("update polling timeout")

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return &UpdateResult{
		CertificateID: certID,
		Status:       "pending",
		Message:      "Update status unknown after maximum polls",
		IsPolling:    true,
	}, fmt.Errorf("update status undetermined")
}

// UpdateCertificateWithPolling updates certificate with automatic polling
func (c *Client) UpdateCertificateWithPolling(
	ctx context.Context,
	oldCertID, certPEM, keyPEM, alias string,
) (*UpdateResult, error) {
	log.Printf("Updating certificate with polling: %s", oldCertID)

	// Step 1: Call UploadUpdateCertificateInstance
	deployRecordID, err := c.UpdateCertificate(ctx, oldCertID, certPEM, keyPEM, alias)
	if err != nil {
		return &UpdateResult{
			Status:  "failed",
			Message: err.Error(),
		}, err
	}

	// Step 2: Handle async task
	if deployRecordID == "0" {
		// Task in progress, poll for completion
		log.Printf("Update task in progress (DeployRecordId=0), starting polling")
		return c.pollUpdateStatus(ctx, oldCertID)
	}

	// Step 3: Task created successfully (DeployRecordId > 0)
	log.Printf("Update task created successfully: DeployRecordId=%s", deployRecordID)
	return &UpdateResult{
		CertificateID:  oldCertID,  // Same ID preserved
		DeployRecordID: deployRecordID,
		Status:        "success",
		Message:       "Certificate update task created successfully",
		IsPolling:    false,
	}, nil
}

// UpdateCertificate updates a certificate while keeping the same certificate ID
// Uses UploadUpdateCertificateInstance API to replace old certificate with new content
// Note: This is an async API that returns DeployRecordId, not CertificateId
func (c *Client) UpdateCertificate(ctx context.Context, oldCertID, certPEM, keyPEM, alias string) (string, error) {
	log.Printf("Updating certificate: %s", oldCertID)

	request := ssl.NewUploadUpdateCertificateInstanceRequest()
	request.OldCertificateId = common.StringPtr(oldCertID)
	request.CertificatePublicKey = common.StringPtr(certPEM)
	request.CertificatePrivateKey = common.StringPtr(keyPEM)

	response, err := c.client.UploadUpdateCertificateInstance(request)
	if err != nil {
		return "", fmt.Errorf("failed to update certificate: %w", err)
	}

	// UploadUpdateCertificateInstanceResponse returns DeployRecordId, not CertificateId
	deployRecordID := ""
	if response.Response.DeployRecordId != nil {
		deployRecordID = fmt.Sprintf("%d", *response.Response.DeployRecordId)
	}

	// Return deployment information
	return deployRecordID, nil
}

// containsDomain checks if certDomain matches or contains the search domain
func containsDomain(certDomain, searchDomain string) bool {
	// For wildcard certificates
	if len(certDomain) > 0 && certDomain[0] == '*' {
		wildcardSuffix := certDomain[2:] // Remove "*."
		if len(searchDomain) > len(wildcardSuffix) {
			return searchDomain[len(searchDomain)-len(wildcardSuffix):] == wildcardSuffix
		}
	}
	return false
}

// Helper functions for safe value extraction
func getString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}


// getStringPtrSlice converts []*string to []string
func getStringPtrSlice(s []*string) []string {
	if s == nil {
		return []string{}
	}
	result := make([]string, 0, len(s))
	for _, item := range s {
		if item != nil {
			result = append(result, *item)
		}
	}
	return result
}

func getBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

