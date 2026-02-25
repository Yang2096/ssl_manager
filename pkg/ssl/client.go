package ssl

import (
	"context"
	"fmt"
	"log"
	"sort"
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

// CertificateInfo represents detailed certificate information
type CertificateInfo struct {
	CertificateID   string   `json:"certificate_id"`
	Domain          string   `json:"domain"`
	Alias           string   `json:"alias,omitempty"`
	Status          string   `json:"status"`
	StatusName      string   `json:"status_name"`
	CertBeginTime   string   `json:"cert_begin_time"`
	CertEndTime     string   `json:"cert_end_time"`
	CommonName      string   `json:"common_name"`
	SubjectAltName  []string `json:"subject_alt_name"`
	Issuer          string   `json:"issuer"`
	ProductZhName   string   `json:"product_zh_name"`
	Deployable      bool     `json:"deployable"`
	EncryptAlgorithm string  `json:"encrypt_algorithm"`
	RenewAble       bool     `json:"renewable"`
	IsVip           bool     `json:"is_vip"`
	IsWildcard      bool     `json:"is_wildcard"`
	IsDv            bool     `json:"is_dv"`
	StatusMsg       string   `json:"status_msg,omitempty"`
	ValidityPeriod  string   `json:"validity_period,omitempty"`
	RemainingDays   int      `json:"remaining_days,omitempty"`
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
// Returns the newest certificate (sorted by CertEndTime descending)
func (c *Client) GetCertificateByDomain(ctx context.Context, domain string) (*CertificateInfo, error) {
	certificates, err := c.GetCertificatesByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, nil
	}
	// GetCertificatesByDomain already sorted by CertEndTime descending, return first (newest)
	return &certificates[0], nil
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

// TransferResult represents the result of certificate instance transfer operation
type TransferResult struct {
	Success        bool   `json:"success"`
	OldCertID      string `json:"old_cert_id"`
	NewCertID      string `json:"new_cert_id"`
	DeployRecordID string `json:"deploy_record_id"`
	Status         string `json:"status"`
	Message        string `json:"message"`
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

// TransferCertificateInstances transfers resource associations from old certificate to new certificate
// Uses UpdateCertificateInstance API with OldCertificateId and CertificateId parameters
// This supports all resource types (cdn, clb, waf, etc.) unlike UploadUpdateCertificateInstance
func (c *Client) TransferCertificateInstances(
	ctx context.Context,
	oldCertID string,
	newCertID string,
	resourceTypes []string,
	resourceTypesRegions []*ssl.ResourceTypeRegions,
) (*TransferResult, error) {
	log.Printf("Transferring certificate instances from %s to %s", oldCertID, newCertID)

	// Default resource types if not specified
	if len(resourceTypes) == 0 {
		resourceTypes = []string{"cdn", "clb", "waf", "live", "ddos", "teo", "apigateway", "vod", "tke", "tcb", "tse", "cos"}
	}
	log.Printf("Resource types for transfer: %v", resourceTypes)

	request := ssl.NewUpdateCertificateInstanceRequest()
	request.OldCertificateId = common.StringPtr(oldCertID)
	request.CertificateId = common.StringPtr(newCertID)
	request.ResourceTypes = common.StringPtrs(resourceTypes)

	// Set resource types regions if provided
	if len(resourceTypesRegions) > 0 {
		request.ResourceTypesRegions = resourceTypesRegions
		log.Printf("Resource types regions for transfer: %+v", resourceTypesRegions)
	}

	response, err := c.client.UpdateCertificateInstance(request)
	if err != nil {
		log.Printf("Failed to transfer certificate instances: %v", err)
		return &TransferResult{
			Success:   false,
			OldCertID: oldCertID,
			NewCertID: newCertID,
			Status:    "failed",
			Message:   err.Error(),
		}, err
	}

	// Log full response for debugging
	log.Printf("UpdateCertificateInstance response: %s", response.ToJsonString())

	deployRecordID := ""
	if response.Response.DeployRecordId != nil {
		deployRecordID = fmt.Sprintf("%d", *response.Response.DeployRecordId)
	}

	log.Printf("Certificate instances transferred successfully: DeployRecordId=%s", deployRecordID)
	return &TransferResult{
		Success:        true,
		OldCertID:      oldCertID,
		NewCertID:      newCertID,
		DeployRecordID: deployRecordID,
		Status:         "success",
		Message:        "Certificate instances transferred successfully",
	}, nil
}

// GetCertificatesByDomain gets all certificates for a specific domain
// Returns certificates sorted by CertEndTime descending (newest first)
func (c *Client) GetCertificatesByDomain(ctx context.Context, domain string) ([]CertificateInfo, error) {
	// Get all certificates matching the domain search
	certificates, err := c.GetCertificateList(ctx, 200, 0, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate list: %w", err)
	}

	// Filter for exact domain match
	var matchedCerts []CertificateInfo
	for _, cert := range certificates {
		// Check exact match in Domain field
		if cert.Domain == domain {
			matchedCerts = append(matchedCerts, cert)
			continue
		}

		// Check if domain is in SubjectAltName (for multi-domain certs)
		for _, san := range cert.SubjectAltName {
			if san == domain {
				matchedCerts = append(matchedCerts, cert)
				break
			}
		}

		// Check wildcard match
		if containsDomain(cert.Domain, domain) {
			matchedCerts = append(matchedCerts, cert)
		}
	}

	// Sort by CertEndTime descending (newest first)
	sortCertificatesByEndTime(matchedCerts)

	return matchedCerts, nil
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

// sortCertificatesByEndTime sorts certificates by CertEndTime descending (newest first)
func sortCertificatesByEndTime(certs []CertificateInfo) {
	sort.Slice(certs, func(i, j int) bool {
		// Parse end times for comparison
		timeI, errI := time.Parse("2006-01-02 15:04:05", certs[i].CertEndTime)
		timeJ, errJ := time.Parse("2006-01-02 15:04:05", certs[j].CertEndTime)

		// If parsing fails, put those at the end
		if errI != nil && errJ != nil {
			return false
		}
		if errI != nil {
			return false
		}
		if errJ != nil {
			return true
		}

		// Sort descending (newest first)
		return timeI.After(timeJ)
	})
}

