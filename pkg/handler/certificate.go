package handler

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yang/ssl-manager/pkg/acme"
	"github.com/yang/ssl-manager/pkg/cert"
	"github.com/yang/ssl-manager/pkg/config"
	"github.com/yang/ssl-manager/pkg/dns"
	notify "github.com/yang/ssl-manager/pkg/notify"
	"github.com/yang/ssl-manager/pkg/response"
	sslClient "github.com/yang/ssl-manager/pkg/ssl"
)

// CertificateHandler handles certificate operations
type CertificateHandler struct {
	cfg         *config.Config
	acmeClient  *acme.Client
	dnsHandler  *dns.ChallengeHandler
	sslClient   *sslClient.Client
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
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	// Create DNS challenge handler
	dnsHandler := dns.NewChallengeHandler(dnsProvider, cfg.ACMEDNSPropagation)

	// Create ACME client
	acmeConfig := acme.NewClientConfig(cfg.ACMEHomeDir, cfg.ACMEAccountEmail, cfg.ACMEStaging)
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

	return &CertificateHandler{
		cfg:         cfg,
		acmeClient:  acmeClient,
		dnsHandler:  dnsHandler,
		sslClient:   sslClient,
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
		func(recordName, recordValue string) bool {
			record, err := h.dnsHandler.AddValidationRecord(ctx, recordName, recordValue, 600)
			if err != nil {
				log.Printf("Failed to add DNS record: %v", err)
				return false
			}
			return record != nil
		},
		func(recordName, recordValue string) bool {
			record := h.dnsHandler.GetRecordByName(recordName)
			if record == nil {
				return false
			}
			err := h.dnsHandler.CleanupRecord(ctx, record)
			return err == nil
		},
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

	return &response.CertificateResponse{
		Success:   true,
		Domain:    domain,
		Domains:   domains,
		CertID:    certID,
		CertPath:  result.CertPath,
		KeyPath:   result.KeyPath,
		CertPEM:   result.CertPEM,
		KeyPEM:    result.KeyPEM,
		Message:   "Certificate issued successfully",
		ExpiresAt: result.ExpiresAt.Format(time.RFC3339),
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
		func(recordName, recordValue string) bool {
			record, err := h.dnsHandler.AddValidationRecord(ctx, recordName, recordValue, 600)
			if err != nil {
				log.Printf("Failed to add DNS record: %v", err)
				return false
			}
			return record != nil
		},
		func(recordName, recordValue string) bool {
			record := h.dnsHandler.GetRecordByName(recordName)
			if record == nil {
				return false
			}
			err := h.dnsHandler.CleanupRecord(ctx, record)
			return err == nil
		},
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

// RenewCertificate renews a certificate using UpdateCertificate API
func (h *CertificateHandler) RenewCertificate(ctx context.Context, domain string, force bool) (*response.CertificateResponse, error) {
	log.Printf("Renewing certificate for %s (force=%v)", domain, force)

	// Step 1: Check if renewal is needed
	if !force {
		certInfo, err := h.CheckCertificateExpiry(ctx, domain)
		if err == nil && certInfo != nil && !certInfo.IsExpiringSoon && !certInfo.IsExpired {
			log.Printf("Certificate for %s is still valid", domain)
			return &response.CertificateResponse{
				Success:       true,
				Domain:        domain,
				Message:       fmt.Sprintf("Certificate is still valid, expires in %d days", certInfo.RemainingDays),
				RemainingDays: certInfo.RemainingDays,
			}, nil
		}
	}

	// Step 2: Get old certificate ID
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

	// Step 3: Request new certificate from ACME
	result, err := h.acmeClient.RequestCertificate(
		ctx,
		[]string{domain},
		func(recordName, recordValue string) bool {
			record, err := h.dnsHandler.AddValidationRecord(ctx, recordName, recordValue, 600)
			if err != nil {
				log.Printf("Failed to add DNS record: %v", err)
				return false
			}
			return record != nil
		},
		func(recordName, recordValue string) bool {
			record := h.dnsHandler.GetRecordByName(recordName)
			if record == nil {
				return false
			}
			err := h.dnsHandler.CleanupRecord(ctx, record)
			return err == nil
		},
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

	// Step 4: Try UpdateCertificate API (one-click update)
	updateResult, updateErr := h.sslClient.UpdateCertificateWithPolling(
		ctx,
		oldCertID,
		result.CertPEM,
		result.KeyPEM,
		domain,
	)

	// Step 5: Handle Update API errors or fallback
	if updateErr != nil {
		log.Printf("UpdateCertificate API failed: %v, falling back to upload", updateErr)

		// Check if error is non-retryable (e.g., not supported)
		if isNonRetryableError(updateErr) {
			// Fallback to traditional upload + deploy
			return h.fallbackRenewal(ctx, domain, result, oldCertID, updateErr)
		}

		// Retryable error - return error immediately
		return response.NewCertificateError(domain, fmt.Sprintf("Certificate update failed: %v", updateErr)), nil
	}

	// Step 6: Success - update local storage
	if _, _, err := h.certStorage.SaveCertificate(ctx, domain, result.CertPEM, result.KeyPEM); err != nil {
		log.Printf("Failed to save certificate locally: %v", err)
		// Don't fail, certificate is already updated in cloud
	}

	// Step 7: Log success
	if updateResult.IsPolling {
		log.Printf("Certificate renewed successfully with polling: DeployRecordId=%s", updateResult.DeployRecordID)
	} else {
		log.Printf("Certificate renewed successfully: DeployRecordId=%s", updateResult.DeployRecordID)
	}

	return &response.CertificateResponse{
		Success:   true,
		Domain:    domain,
		Domains:   []string{domain},
		CertID:    oldCertID, // Same ID preserved
		CertPath:  result.CertPath,
		KeyPath:   result.KeyPath,
		CertPEM:   result.CertPEM,
		KeyPEM:    result.KeyPEM,
		Message:   "Certificate renewed successfully (ID preserved)",
		ExpiresAt: result.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// isNonRetryableError checks if error is non-retryable
func isNonRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	nonRetryableErrors := []string{
		"UnsupportedOperation",
		"CertificateHostDeployCanNotAllow",
		"CertificateWhiteFuncError",
		"FailedOperation.CertificateHostResourceInnerInterrupt",
	}
	for _, nonRetryable := range nonRetryableErrors {
		if strings.Contains(errStr, nonRetryable) {
			return true
		}
	}
	return false
}

// fallbackRenewal handles renewal when UpdateCertificate API is not available
func (h *CertificateHandler) fallbackRenewal(
	ctx context.Context,
	domain string,
	acmeResult *acme.CertificateResult,
	oldCertID string,
	updateErr error,
) (*response.CertificateResponse, error) {
	log.Printf("Using fallback renewal for %s", domain)

	// Step 1: Upload as new certificate
	newCertID, err := h.sslClient.UploadCertificate(ctx, acmeResult.CertPEM, acmeResult.KeyPEM)
	if err != nil {
		log.Printf("Fallback upload failed: %v", err)
		return response.NewCertificateError(domain, fmt.Sprintf("Both update and fallback failed: %v", err)), nil
	}

	log.Printf("Fallback: Uploaded new certificate with ID: %s", newCertID)

	// Step 2: Save local copy
	if _, _, err := h.certStorage.SaveCertificate(ctx, domain, acmeResult.CertPEM, acmeResult.KeyPEM); err != nil {
		log.Printf("Failed to save certificate locally: %v", err)
	}

	// Step 3: Notify with warning (log only)
	log.Printf("FALLBACK: Certificate renewed using fallback method. Old ID: %s, New ID: %s, Reason: %s",
		oldCertID, newCertID, updateErr.Error())

	return &response.CertificateResponse{
		Success:   true,
		Domain:    domain,
		CertID:    newCertID, // New ID
		CertPath:  acmeResult.CertPath,
		KeyPath:   acmeResult.KeyPath,
		CertPEM:   acmeResult.CertPEM,
		KeyPEM:    acmeResult.KeyPEM,
		Message:   "Certificate renewed using fallback method (new ID created)",
		ExpiresAt: acmeResult.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// CheckCertificateExpiry checks the expiry status of a certificate
func (h *CertificateHandler) CheckCertificateExpiry(ctx context.Context, domain string) (*CertificateExpiryInfo, error) {
	// Try to get from local storage first
	certPEM, _, err := h.certStorage.LoadBoth(ctx, domain)
	if err == nil && certPEM != "" {
		validator := cert.NewValidator(h.cfg.CertExpiryWarningDays)
		info, err := validator.ValidateCertificate(certPEM)
		if err == nil {
			return &CertificateExpiryInfo{
				Domain:         domain,
				RemainingDays:  info.RemainingDays,
				IsExpiringSoon: info.IsExpiringSoon,
				IsExpired:      info.IsExpired,
				NotAfter:       info.NotAfter,
			}, nil
		}
	}

	// Check from SSL service
	cert, err := h.sslClient.GetCertificateByDomain(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	if cert == nil {
		return nil, nil
	}

	endTime := cert.CertEndTime
	remainingDays, err := calculateRemainingDays(endTime)
	if err != nil {
		return nil, err
	}

	return &CertificateExpiryInfo{
		Domain:         domain,
		RemainingDays:  remainingDays,
		IsExpiringSoon: remainingDays <= h.cfg.CertExpiryWarningDays,
		IsExpired:      remainingDays <= 0,
		NotAfter:       parseEndTime(endTime),
	}, nil
}

// GetCertificate retrieves certificate content
func (h *CertificateHandler) GetCertificate(ctx context.Context, domain string) (string, string, error) {
	return h.certStorage.LoadBoth(ctx, domain)
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

// DeployCertificate deploys a certificate to cloud resources
func (h *CertificateHandler) DeployCertificate(ctx context.Context, domain, resourceType string, resourceIDs []string) (*response.DeploymentResponse, error) {
	log.Printf("Deploying certificate for %s to %s", domain, resourceType)

	// Get certificate ID for domain
	certID, err := h.sslClient.GetCertificateID(ctx, domain)
	if err != nil || certID == "" {
		return response.NewDeploymentError(domain, resourceType, "Certificate not found"), nil
	}

	// Deploy
	deployment := sslClient.NewDeploymentOperations(h.sslClient)
	result, err := deployment.Deploy(ctx, certID, resourceType, resourceIDs, domain)
	if err != nil {
		return response.NewDeploymentError(domain, resourceType, err.Error()), nil
	}

	if result.Success {
		h.notifier.NotifyDeployment(ctx, domain, resourceType, result.DeploymentID, true)
	}

	return response.NewDeploymentSuccess(domain, resourceType, result.DeploymentID), nil
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

			result, err := h.RenewCertificate(ctx, domain, true)
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

// CertificateExpiryInfo holds certificate expiry information
type CertificateExpiryInfo struct {
	Domain         string    `json:"domain"`
	RemainingDays  int       `json:"remaining_days"`
	IsExpiringSoon bool      `json:"is_expiring_soon"`
	IsExpired      bool      `json:"is_expired"`
	NotAfter       time.Time `json:"not_after"`
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

func parseEndTime(endTime string) time.Time {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, endTime); err == nil {
			return t
		}
	}

	return time.Time{}
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
