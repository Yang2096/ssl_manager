package handler

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"github.com/yang/ssl-manager/pkg/acme"
	"github.com/yang/ssl-manager/pkg/cert"
	"github.com/yang/ssl-manager/pkg/config"
	"github.com/yang/ssl-manager/pkg/dns"
	notify "github.com/yang/ssl-manager/pkg/notify"
	"github.com/yang/ssl-manager/pkg/qiniu"
	"github.com/yang/ssl-manager/pkg/response"
	sslClient "github.com/yang/ssl-manager/pkg/ssl"
)

// CertificateHandler handles certificate operations
type CertificateHandler struct {
	cfg         *config.Config
	acmeClient  *acme.Client
	dnsHandler  *dns.ChallengeHandler
	sslClient   *sslClient.Client
	qiniuClient *qiniu.Client
	certStorage *cert.CertificateStorage
	notifier    *Notifier
}

// HandlerConfig holds configuration for the certificate handler
type HandlerConfig struct {
	Config      *config.Config
	ACMEClient  *acme.Client
	DNSHandler  *dns.ChallengeHandler
	SSLClient   *sslClient.Client
	CertStorage *cert.CertificateStorage
}

// NewCertificateHandler creates a new certificate handler
func NewCertificateHandler(cfg *config.Config) (*CertificateHandler, error) {
	// Create DNS provider
	dnsProvider, err := dns.NewTencentCloudProvider(
		cfg.TencentSecretID,
		cfg.TencentSecretKey,
		cfg.TencentRegion,
		cfg.ACMEDNSPropagation,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	// Create DNS challenge handler
	dnsHandler := dns.NewChallengeHandler(dnsProvider, cfg.ACMEDNSPropagation)

	// Create ACME client
	acmeConfig := acme.NewClientConfig(cfg.ACMEHomeDir, cfg.ACMEAccountEmail, cfg.ACMEStaging)

	// Add DNS configuration
	acmeConfig.DNSResolvers = cfg.ACMEDNSResolvers
	acmeConfig.DNSTimeout = cfg.ACMEDNSTimeout

	acmeClient, err := acme.NewClient(acmeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Set DNS provider for ACME client
	acmeClient.SetDNSProvider(dnsProvider)

	// Create SSL client
	sslClient, err := sslClient.NewClient(
		cfg.TencentSecretID,
		cfg.TencentSecretKey,
		cfg.TencentRegion,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSL client: %w", err)
	}

	// Create certificate storage
	certStorage, err := cert.NewCertificateStorage(cfg.ACMEHomeDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate storage: %w", err)
	}

	// Create notifier
	notifier := NewNotifier(
		cfg.NotifyWebhook,
		cfg.NotifyEnabled,
	)

	// Create Qiniu client (optional)
	var qiniuClient *qiniu.Client
	if cfg.QiniuAccessKey != "" && cfg.QiniuSecretKey != "" {
		qiniuClient, err = qiniu.NewClient(cfg.QiniuAccessKey, cfg.QiniuSecretKey)
		if err != nil {
			log.Printf("Warning: Failed to create Qiniu client: %v", err)
			// Don't fail, Qiniu is optional
		} else {
			log.Printf("Qiniu client initialized successfully")
		}
	}

	return &CertificateHandler{
		cfg:         cfg,
		acmeClient:  acmeClient,
		dnsHandler:  dnsHandler,
		sslClient:   sslClient,
		qiniuClient: qiniuClient,
		certStorage: certStorage,
		notifier:    notifier,
	}, nil
}

// IsReady checks if the handler is ready for operations
func (h *CertificateHandler) IsReady() bool {
	return h.cfg.TencentSecretID != "" && h.cfg.TencentSecretKey != ""
}

// IssueCertificate issues a new certificate
func (h *CertificateHandler) IssueCertificate(ctx context.Context, domain string, extraDomains []string) (*response.CertificateResponse, error) {
	log.Printf("Starting certificate issuance for %s", domain)

	if !h.IsReady() {
		return response.NewCertificateError(domain, "DNSPod credentials not configured"), nil
	}

	// Build domain list
	domains := []string{domain}
	domains = append(domains, extraDomains...)
	domains = unique(domains)

	// Request certificate from ACME
	result, err := h.acmeClient.RequestCertificate(
		ctx,
		domains,
	)

	if err != nil {
		log.Printf("Certificate issuance failed for %s: %v", domain, err)
		return response.NewCertificateError(domain, err.Error()), nil
	}

	// Clean up DNS records
	if cleanupErr := h.dnsHandler.CleanupRecords(ctx); cleanupErr != nil {
		log.Printf("Failed to cleanup DNS records: %v", cleanupErr)
	}

	if !result.Success {
		return response.NewCertificateError(domain, result.Message), nil
	}

	// Upload certificate to Tencent Cloud
	certID, err := h.sslClient.UploadCertificate(ctx, result.CertPEM, result.KeyPEM)
	if err != nil {
		log.Printf("Failed to upload certificate to SSL service: %v", err)
		// Don't fail here, certificate is still saved locally
		certID = ""
	} else {
		log.Printf("Certificate uploaded to SSL service: %s", certID)
		h.notifier.NotifySuccess(ctx, domain, "issued", certID)
	}

	// Sync to Qiniu if the domain is on Qiniu
	qiniuCertID := h.syncToQiniu(ctx, domain, result.CertPEM, result.KeyPEM)

	return &response.CertificateResponse{
		Success:     true,
		Domain:      domain,
		Domains:     domains,
		CertID:      certID,
		QiniuCertID: qiniuCertID,
		CertPath:    result.CertPath,
		KeyPath:     result.KeyPath,
		CertPEM:     result.CertPEM,
		KeyPEM:      result.KeyPEM,
		Message:     "Certificate issued successfully",
		ExpiresAt:   result.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// IssueCertificateLocal issues a certificate locally (without uploading)
func (h *CertificateHandler) IssueCertificateLocal(ctx context.Context, domain string, extraDomains []string) (*response.CertificateResponse, error) {
	log.Printf("Starting local certificate issuance for %s", domain)

	if !h.IsReady() {
		return response.NewCertificateError(domain, "DNSPod credentials not configured"), nil
	}

	// Build domain list
	domains := []string{domain}
	domains = append(domains, extraDomains...)
	domains = unique(domains)

	// Request certificate from ACME
	result, err := h.acmeClient.RequestCertificate(
		ctx,
		domains,
	)

	if err != nil {
		log.Printf("Certificate issuance failed for %s: %v", domain, err)
		return response.NewCertificateError(domain, err.Error()), nil
	}

	// Clean up DNS records
	if cleanupErr := h.dnsHandler.CleanupRecords(ctx); cleanupErr != nil {
		log.Printf("Failed to cleanup DNS records: %v", cleanupErr)
	}

	if !result.Success {
		return response.NewCertificateError(domain, result.Message), nil
	}

	return &response.CertificateResponse{
		Success:   true,
		Domain:    domain,
		Domains:   domains,
		CertPath:  result.CertPath,
		KeyPath:   result.KeyPath,
		CertPEM:   result.CertPEM,
		KeyPEM:    result.KeyPEM,
		Message:   "Certificate issued successfully locally",
		ExpiresAt: result.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// RenewCertificate renews a certificate using UploadCertificate + TransferCertificateInstances
// Note: This always performs renewal. For conditional renewal based on expiry, use CheckAndRenew.
func (h *CertificateHandler) RenewCertificate(ctx context.Context, domain string) (*response.CertificateResponse, error) {
	log.Printf("Renewing certificate for %s", domain)

	// Step 1: Get old (latest available) certificate ID
	oldCertID, err := h.sslClient.GetCertificateID(ctx, domain)
	if err != nil {
		return response.NewCertificateError(domain, fmt.Sprintf("Failed to get certificate ID: %v", err)), nil
	}

	// No existing certificate found, use normal issuance
	if oldCertID == "" {
		log.Printf("No existing certificate found for %s, creating new one", domain)
		return h.IssueCertificate(ctx, domain, nil)
	}

	log.Printf("Found existing certificate ID: %s for domain %s", oldCertID, domain)

	// Step 2: Request new certificate from ACME
	result, err := h.acmeClient.RequestCertificate(
		ctx,
		[]string{domain},
	)

	if err != nil || !result.Success {
		log.Printf("Certificate request from ACME failed for %s: %v", domain, err)
		return response.NewCertificateError(domain, err.Error()), nil
	}

	// Clean up DNS records
	if cleanupErr := h.dnsHandler.CleanupRecords(ctx); cleanupErr != nil {
		log.Printf("Failed to cleanup DNS records: %v", cleanupErr)
	}

	log.Printf("New certificate obtained from ACME for %s", domain)

	// Step 3: Upload new certificate to get newCertID
	newCertID, err := h.sslClient.UploadCertificate(ctx, result.CertPEM, result.KeyPEM)
	if err != nil {
		log.Printf("Failed to upload new certificate: %v", err)
		return response.NewCertificateError(domain, fmt.Sprintf("Failed to upload certificate: %v", err)), nil
	}

	log.Printf("New certificate uploaded with ID: %s", newCertID)

	// Step 4: Check if has explicit UpdateConfig and transfer instances
	resourceConfigs := h.cfg.GetUpdateConfigForDomain(domain)
	if len(resourceConfigs) > 0 && oldCertID != "" {
		log.Printf("Domain %s has explicit UpdateConfig, transferring instances", domain)

		resourceTypes, resourceTypesRegions := convertResourceConfigs(resourceConfigs)
		log.Printf("Resource types for %s: %v", domain, resourceTypes)

		transferResult, transferErr := h.sslClient.TransferCertificateInstances(
			ctx,
			oldCertID,
			newCertID,
			resourceTypes,
			resourceTypesRegions,
		)

		if transferErr != nil {
			log.Printf("Warning: Failed to transfer certificate instances: %v", transferErr)
			// Don't fail - the new certificate is already uploaded
		} else {
			log.Printf("Certificate instances transferred: DeployRecordId=%s", transferResult.DeployRecordID)
		}
	} else {
		log.Printf("Domain %s has no explicit UpdateConfig, skipping resource transfer", domain)
	}

	// Step 5: Save local copy
	if _, _, err := h.certStorage.SaveCertificate(ctx, domain, result.CertPEM, result.KeyPEM); err != nil {
		log.Printf("Failed to save certificate locally: %v", err)
		// Don't fail, certificate is already uploaded
	}

	// Step 6: Sync to Qiniu if the domain is on Qiniu
	qiniuCertID := h.syncToQiniu(ctx, domain, result.CertPEM, result.KeyPEM)

	// Step 7: Cleanup expired certificates
	if cleanupErr := h.CleanupExpiredCertificates(ctx, domain); cleanupErr != nil {
		log.Printf("Warning: Failed to cleanup expired certificates: %v", cleanupErr)
		// Don't fail - renewal was successful
	}

	return &response.CertificateResponse{
		Success:     true,
		Domain:      domain,
		Domains:     []string{domain},
		CertID:      newCertID,
		OldCertID:   oldCertID,
		QiniuCertID: qiniuCertID,
		CertPath:    result.CertPath,
		KeyPath:     result.KeyPath,
		CertPEM:     result.CertPEM,
		KeyPEM:      result.KeyPEM,
		Message:     "Certificate renewed successfully",
		ExpiresAt:   result.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// CleanupExpiredCertificates cleans up expired certificates for a domain
// Only deletes expired certificates when there's a valid certificate available
func (h *CertificateHandler) CleanupExpiredCertificates(ctx context.Context, domain string) error {
	log.Printf("Cleaning up expired certificates for %s", domain)

	// Get all certificates for this domain
	certificates, err := h.sslClient.GetCertificatesByDomain(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get certificates for cleanup: %w", err)
	}

	// If only one or no certificate, nothing to clean up
	if len(certificates) <= 1 {
		log.Printf("Only %d certificate(s) for %s, skipping cleanup", len(certificates), domain)
		return nil
	}

	log.Printf("Found %d certificates for %s", len(certificates), domain)

	// Find certificates to delete (expired or expiring within 7 days, except the newest)
	var toDelete []string
	now := time.Now()
	expiringThreshold := now.Add(7 * 24 * time.Hour)

	for i, cert := range certificates {
		// Skip the first (newest) certificate
		if i == 0 {
			continue
		}

		// Parse end time
		endTime, err := time.Parse("2006-01-02 15:04:05", cert.CertEndTime)
		if err != nil {
			log.Printf("Warning: Failed to parse end time for certificate %s: %v", cert.CertificateID, err)
			continue
		}

		// Delete if expired or expiring within 7 days
		if endTime.Before(expiringThreshold) {
			log.Printf("Marking certificate %s for deletion (expires: %s)", cert.CertificateID, cert.CertEndTime)
			toDelete = append(toDelete, cert.CertificateID)
		}
	}

	// Delete old certificates
	for _, certID := range toDelete {
		if err := h.sslClient.DeleteCertificate(ctx, certID); err != nil {
			log.Printf("Warning: Failed to delete certificate %s: %v", certID, err)
		} else {
			log.Printf("Deleted expired certificate: %s", certID)
		}
	}

	if len(toDelete) > 0 {
		log.Printf("Cleaned up %d expired certificate(s) for %s", len(toDelete), domain)
	}

	return nil
}

// syncToQiniu syncs the certificate to Qiniu if the domain is used on Qiniu
// Returns the Qiniu certificate ID if synced, empty string otherwise
func (h *CertificateHandler) syncToQiniu(ctx context.Context, domain, certPEM, keyPEM string) string {
	if h.qiniuClient == nil || !h.qiniuClient.IsEnabled() {
		log.Printf("[Qiniu] Client not configured, skipping sync")
		return ""
	}

	// Get all existing certificates for this domain to check if it's on Qiniu
	existingCerts, err := h.qiniuClient.GetCertificatesByDomain(ctx, domain)
	if err != nil {
		log.Printf("[Qiniu] Warning: Failed to get certificates for domain: %v", err)
		// Don't fail the whole operation, just skip
		return ""
	}

	if len(existingCerts) == 0 {
		log.Printf("[Qiniu] Domain %s is not on Qiniu, skipping sync", domain)
		return ""
	}

	log.Printf("[Qiniu] Domain %s is on Qiniu, uploading certificate", domain)

	// Get domain info to check current certificate in use
	domainInfo, err := h.qiniuClient.GetDomainInfo(ctx, domain)
	if err != nil {
		log.Printf("[Qiniu] Warning: Failed to get domain info: %v", err)
		// Continue anyway, we just won't have the current cert info
	}

	var currentCertID string
	if domainInfo != nil && domainInfo.Https != nil {
		currentCertID = domainInfo.Https.CertID
		log.Printf("[Qiniu] Current certificate in use: %s", currentCertID)
	}

	// Upload new certificate
	qiniuCertID, err := h.qiniuClient.UploadCertificate(ctx, domain, domain, keyPEM, certPEM)
	if err != nil {
		log.Printf("[Qiniu] Failed to upload certificate: %v", err)
		return ""
	}

	log.Printf("[Qiniu] Certificate uploaded successfully: %s", qiniuCertID)

	// Enable HTTPS for the domain with the new certificate
	if err := h.qiniuClient.SSLize(ctx, domain, qiniuCertID); err != nil {
		log.Printf("[Qiniu] Warning: Failed to enable HTTPS: %v", err)
		// Don't fail, certificate is uploaded
	}

	// If there were >= 2 existing certificates, delete the oldest one (if not in use)
	if len(existingCerts) >= 2 {
		// Find the certificate with the oldest createTime
		var oldestCert *qiniu.CertificateInfo
		for i := range existingCerts {
			if oldestCert == nil || existingCerts[i].CreateTime < oldestCert.CreateTime {
				oldestCert = &existingCerts[i]
			}
		}

		if oldestCert != nil && oldestCert.CertID != qiniuCertID {
			// Check if the oldest certificate is currently in use
			if oldestCert.CertID == currentCertID {
				log.Printf("[Qiniu] Skipping deletion of oldest certificate %s: currently in use by domain", oldestCert.CertID)
			} else {
				if err := h.qiniuClient.Delete(ctx, oldestCert.CertID); err != nil {
					log.Printf("[Qiniu] Warning: Failed to delete oldest certificate %s: %v", oldestCert.CertID, err)
				} else {
					log.Printf("[Qiniu] Oldest certificate deleted: %s (createTime: %d)", oldestCert.CertID, oldestCert.CreateTime)
				}
			}
		}
	}

	return qiniuCertID
}

// ListCertificates lists all certificates from Tencent Cloud SSL service
func (h *CertificateHandler) ListCertificates(ctx context.Context, searchDomain string) (*response.ListResponse, error) {
	// Get certificates from SSL service
	limit := 100
	offset := 0
	certificates, err := h.sslClient.GetCertificateList(ctx, limit, offset, searchDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificates from SSL service: %w", err)
	}

	// Add remaining days calculation to each certificate
	for i := range certificates {
		cert := &certificates[i]
		if cert.CertEndTime != "" {
			if days, err := calculateRemainingDays(cert.CertEndTime); err == nil {
				cert.RemainingDays = days
			}
		}
	}

	return response.NewListSuccess(certificates, len(certificates)), nil
}

// UploadCertificate uploads an existing certificate to Tencent Cloud
func (h *CertificateHandler) UploadCertificate(ctx context.Context, domain, certDir string) (*response.CertificateResponse, error) {
	log.Printf("Uploading certificate for %s from %s", domain, certDir)

	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return response.NewCertificateError(domain, "Failed to read certificate"), nil
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return response.NewCertificateError(domain, "Failed to read private key"), nil
	}

	certID, err := h.sslClient.UploadCertificate(ctx, string(certPEM), string(keyPEM))
	if err != nil {
		return response.NewCertificateError(domain, err.Error()), nil
	}

	h.notifier.NotifySuccess(ctx, domain, "uploaded", certID)

	return &response.CertificateResponse{
		Success: true,
		Domain:  domain,
		CertID:  certID,
		Message: "Certificate uploaded successfully",
	}, nil
}


// CheckAndRenew checks and renews expiring certificates
func (h *CertificateHandler) CheckAndRenew(ctx context.Context) (*response.CheckResponse, error) {
	log.Printf("Starting automatic certificate check and renewal")

	// Get certificates from SSL service
	expiryChecker := cert.NewExpiryChecker(h.cfg.CertExpiryWarningDays)
	summary, err := expiryChecker.CheckAllCertificates(ctx, h.sslClient)
	if err != nil {
		return nil, fmt.Errorf("failed to check certificates: %w", err)
	}

	// Notify results
	if summary.ExpiringSoon > 0 || summary.Expired > 0 {
		h.notifier.NotifyCheckResults(ctx, summary.Total, summary.ExpiringSoon, summary.Expired)
	}

	// Renew expiring certificates
	var renewedCertificates []string
	var failedRenewals []string

	for _, certStatus := range summary.Certificates {
		if certStatus.Urgency == cert.UrgencyExpired || certStatus.Urgency == cert.UrgencyCritical || certStatus.Urgency == cert.UrgencyWarning {
			domain := certStatus.Domain
			log.Printf("Renewing certificate for %s", domain)

			result, err := h.RenewCertificate(ctx, domain)
			if err != nil {
				log.Printf("Failed to renew certificate for %s: %v", domain, err)
				failedRenewals = append(failedRenewals, domain)
			} else if result.Success {
				renewedCertificates = append(renewedCertificates, domain)
			} else {
				failedRenewals = append(failedRenewals, domain)
			}
		}
	}

	return response.NewCheckResponse(
		summary.Total,
		summary.Valid,
		summary.ExpiringSoon,
		summary.Expired,
		toResponseStatus(summary.Certificates),
	), nil
}

// Notifier wraps the webhook notifier
type Notifier struct {
	webhook *notify.WebhookNotifier
}

// NewNotifier creates a new notifier
func NewNotifier(webhookURL string, enabled bool) *Notifier {
	return &Notifier{
		webhook: notify.NewWebhookNotifier(webhookURL, enabled),
	}
}

// NotifySuccess sends a success notification
func (n *Notifier) NotifySuccess(ctx context.Context, domain, action, certID string) {
	n.webhook.NotifySuccess(ctx, domain, action, certID)
}

// NotifyFailure sends a failure notification
func (n *Notifier) NotifyFailure(ctx context.Context, domain, action, errorMsg string) {
	n.webhook.NotifyFailure(ctx, domain, action, errorMsg)
}

// NotifyCheckResults sends check results notification
func (n *Notifier) NotifyCheckResults(ctx context.Context, total, expiring, expired int) {
	n.webhook.NotifyCheckResults(ctx, total, expiring, expired)
}

// NotifyDeployment sends a deployment notification
func (n *Notifier) NotifyDeployment(ctx context.Context, domain, resourceType, deploymentID string, success bool) {
	n.webhook.NotifyDeployment(ctx, domain, resourceType, deploymentID, success)
}

// Helper functions

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

func calculateRemainingDays(endTime string) (int, error) {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, endTime); err == nil {
			duration := time.Until(t)
			return int(duration.Hours() / 24), nil
		}
	}

	return 0, fmt.Errorf("unable to parse end time: %s", endTime)
}

func toResponseStatus(statuses []cert.CertificateStatus) []response.CertificateStatus {
	result := make([]response.CertificateStatus, 0, len(statuses))
	for _, s := range statuses {
		result = append(result, response.CertificateStatus{
			Domain:        s.Domain,
			CertID:        s.CertificateID,
			RemainingDays: s.RemainingDays,
			Status:        s.Status,
			Urgency:       response.UrgencyLevel(s.Urgency),
		})
	}
	return result
}

// convertResourceConfigs converts ResourceUpdateConfig slice to API format
// Returns resourceTypes (string slice) and resourceTypesRegions (SDK format)
func convertResourceConfigs(configs []config.ResourceUpdateConfig) ([]string, []*ssl.ResourceTypeRegions) {
	resourceTypes := make([]string, 0, len(configs))
	var resourceTypesRegions []*ssl.ResourceTypeRegions

	for _, cfg := range configs {
		resourceTypes = append(resourceTypes, cfg.Type)

		// If regions are specified, create ResourceTypeRegions entry
		if len(cfg.Regions) > 0 {
			regions := make([]*string, 0, len(cfg.Regions))
			for _, region := range cfg.Regions {
				regions = append(regions, common.StringPtr(region))
			}
			resourceTypesRegions = append(resourceTypesRegions, &ssl.ResourceTypeRegions{
				ResourceType: common.StringPtr(cfg.Type),
				Regions:      regions,
			})
		}
	}

	return resourceTypes, resourceTypesRegions
}
