package ssl

import (
	"context"
	"fmt"
)

// CertificateOperations provides certificate-specific operations
type CertificateOperations struct {
	client *Client
}

// NewCertificateOperations creates a new certificate operations handler
func NewCertificateOperations(client *Client) *CertificateOperations {
	return &CertificateOperations{client: client}
}

// UploadResult represents the result of uploading a certificate
type UploadResult struct {
	CertificateID string `json:"certificate_id"`
	Success      bool   `json:"success"`
	Message      string `json:"message"`
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
	EncryptAlgorithm string   `json:"encrypt_algorithm"`
	RenewAble      bool     `json:"renewable"`
	IsVip           bool     `json:"is_vip"`
	IsWildcard      bool     `json:"is_wildcard"`
	IsDv            bool     `json:"is_dv"`
	StatusMsg       string   `json:"status_msg,omitempty"`
	ValidityPeriod  string   `json:"validity_period,omitempty"`
	RemainingDays   int      `json:"remaining_days,omitempty"`
}

// Upload uploads a certificate and returns the result
func (o *CertificateOperations) Upload(ctx context.Context, certPEM, keyPEM string) (*UploadResult, error) {
	certID, err := o.client.UploadCertificate(ctx, certPEM, keyPEM)
	if err != nil {
		return &UploadResult{
			Success: false,
			Message: err.Error(),
		}, err
	}

	return &UploadResult{
		CertificateID: certID,
		Success:      true,
		Message:      "Certificate uploaded successfully",
	}, nil
}

// GetByDomain retrieves certificate information for a domain
func (o *CertificateOperations) GetByDomain(ctx context.Context, domain string) (*CertificateInfo, error) {
	return o.client.GetCertificateByDomain(ctx, domain)
}

// GetID retrieves a certificate ID for a domain
func (o *CertificateOperations) GetID(ctx context.Context, domain string) (string, error) {
	certID, err := o.client.GetCertificateID(ctx, domain)
	if err != nil {
		return "", err
	}
	return certID, nil
}

// Delete removes a certificate by ID
func (o *CertificateOperations) Delete(ctx context.Context, certID string) error {
	return o.client.DeleteCertificate(ctx, certID)
}

// CheckStatus retrieves the status of a certificate
func (o *CertificateOperations) CheckStatus(ctx context.Context, certID string) (*CertificateInfo, error) {
	return o.client.CheckCertificateStatus(ctx, certID)
}

// Update updates an existing certificate with new content
func (o *CertificateOperations) Update(ctx context.Context, oldCertID, certPEM, keyPEM, alias string) (*UploadResult, error) {
	newCertID, err := o.client.UpdateCertificate(ctx, oldCertID, certPEM, keyPEM, alias)
	if err != nil {
		return &UploadResult{
			Success: false,
			Message: err.Error(),
		}, err
	}

	return &UploadResult{
		CertificateID: newCertID,
		Success:      true,
		Message:      "Certificate updated successfully",
	}, nil
}

// List retrieves certificates with optional filtering
func (o *CertificateOperations) List(ctx context.Context, limit, offset int, searchKey string) ([]CertificateInfo, error) {
	return o.client.GetCertificateList(ctx, limit, offset, searchKey)
}

// ValidateCertificate validates that a certificate and key are properly formatted
func ValidateCertificate(certPEM, keyPEM string) error {
	if certPEM == "" {
		return fmt.Errorf("certificate PEM is empty")
	}
	if keyPEM == "" {
		return fmt.Errorf("private key PEM is empty")
	}

	// Check for proper PEM headers
	if !containsPEMHeader(certPEM, "CERTIFICATE") {
		return fmt.Errorf("invalid certificate PEM format")
	}
	if !containsPEMHeader(keyPEM, "PRIVATE KEY") {
		return fmt.Errorf("invalid private key PEM format")
	}

	return nil
}

// containsPEMHeader checks if PEM content has the specified header
func containsPEMHeader(content, header string) bool {
	return len(content) > 0 &&
		(content[0:len("-----BEGIN")] == "-----BEGIN" ||
	 contentContains(content, "-----BEGIN "+header))
}

func contentContains(content, substr string) bool {
	for i := 0; i <= len(content)-len(substr); i++ {
		if content[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
