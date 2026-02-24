package response

import (
	"encoding/json"
	"fmt"
	"time"
)

// UrgencyLevel represents the urgency level of a certificate
type UrgencyLevel string

const (
	UrgencyOk       UrgencyLevel = "ok"
	UrgencyWarning  UrgencyLevel = "warning"
	UrgencyCritical UrgencyLevel = "critical"
	UrgencyExpired  UrgencyLevel = "expired"
)

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string        `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorInfo  `json:"error,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
}

// ErrorInfo represents error details
type ErrorInfo struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// CertificateResponse represents a certificate operation response
type CertificateResponse struct {
	Success       bool     `json:"success"`
	Domain        string   `json:"domain,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	CertID        string   `json:"cert_id,omitempty"`
	OldCertID     string   `json:"old_cert_id,omitempty"` // Old certificate ID (for renewal)
	QiniuCertID   string   `json:"qiniu_cert_id,omitempty"`
	CertPath      string   `json:"cert_path,omitempty"`
	KeyPath       string   `json:"key_path,omitempty"`
	CSRPath       string   `json:"csr_path,omitempty"`
	CertPEM       string   `json:"cert_pem,omitempty"`
	KeyPEM        string   `json:"key_pem,omitempty"`
	Message       string   `json:"message"`
	RemainingDays int      `json:"remaining_days,omitempty"`
	ExpiresAt     string   `json:"expires_at,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// DeploymentResponse represents a deployment operation response
type DeploymentResponse struct {
	Success     bool     `json:"success"`
	Domain      string   `json:"domain,omitempty"`
	ResourceType string   `json:"resource_type,omitempty"`
	ResourceIDs []string `json:"resource_ids,omitempty"`
	DeploymentID string   `json:"deployment_id,omitempty"`
	Status      string   `json:"status,omitempty"`
	Message     string   `json:"message"`
	Error       string   `json:"error,omitempty"`
}

// ListResponse represents a list operation response
type ListResponse struct {
	Success    bool         `json:"success"`
	Total      int          `json:"total,omitempty"`
	Items      interface{}   `json:"items,omitempty"`
	Message    string       `json:"message,omitempty"`
	Error      string       `json:"error,omitempty"`
}

// RenewalResponse represents a renewal operation response
type RenewalResponse struct {
	Success       bool   `json:"success"`
	Domain        string `json:"domain,omitempty"`
	OldCertID     string `json:"old_cert_id,omitempty"`
	NewCertID     string `json:"new_cert_id,omitempty"`
	RemainingDays int    `json:"remaining_days,omitempty"`
	Message       string `json:"message"`
	Error         string `json:"error,omitempty"`
}

// CheckResponse represents a certificate check response
type CheckResponse struct {
	Success      bool               `json:"success"`
	Total        int                `json:"total"`
	Valid        int                `json:"valid"`
	ExpiringSoon  int                `json:"expiring_soon"`
	Expired      int                `json:"expired"`
	Certificates []CertificateStatus `json:"certificates,omitempty"`
	Message      string             `json:"message,omitempty"`
}

// CertificateStatus represents certificate status in check response
type CertificateStatus struct {
	Domain        string        `json:"domain"`
	CertID        string        `json:"cert_id,omitempty"`
	RemainingDays int           `json:"remaining_days"`
	Status        string        `json:"status"`
	Urgency       UrgencyLevel  `json:"urgency,omitempty"`
}

// NewSuccess creates a success response
func NewSuccess(message string, data interface{}) *Response {
	return &Response{
		Success:  true,
		Message:  message,
		Data:     data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewError creates an error response
func NewError(code, message string, details string) *Response {
	return &Response{
		Success: false,
		Message: "Operation failed",
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewCertificateSuccess creates a successful certificate response
func NewCertificateSuccess(domain string, domains []string, certID string) *CertificateResponse {
	return &CertificateResponse{
		Success: true,
		Domain:  domain,
		Domains: domains,
		CertID:  certID,
		Message: "Certificate operation completed successfully",
	}
}

// NewCertificateError creates a certificate error response
func NewCertificateError(domain, message string) *CertificateResponse {
	return &CertificateResponse{
		Success: false,
		Domain:  domain,
		Message: message,
		Error:   message,
	}
}

// NewDeploymentSuccess creates a successful deployment response
func NewDeploymentSuccess(domain, resourceType string, deploymentID string) *DeploymentResponse {
	return &DeploymentResponse{
		Success:     true,
		Domain:      domain,
		ResourceType: resourceType,
		DeploymentID: deploymentID,
		Message:     "Deployment initiated successfully",
	}
}

// NewDeploymentError creates a deployment error response
func NewDeploymentError(domain, resourceType, errorMsg string) *DeploymentResponse {
	return &DeploymentResponse{
		Success:     false,
		Domain:      domain,
		ResourceType: resourceType,
		Message:     "Deployment failed",
		Error:       errorMsg,
	}
}

// NewListSuccess creates a successful list response
func NewListSuccess(items interface{}, total int) *ListResponse {
	return &ListResponse{
		Success: true,
		Items:   items,
		Total:   total,
	}
}

// NewCheckResponse creates a certificate check response
func NewCheckResponse(total, valid, expiringSoon, expired int, certificates []CertificateStatus) *CheckResponse {
	return &CheckResponse{
		Success:      true,
		Total:        total,
		Valid:        valid,
		ExpiringSoon:  expiringSoon,
		Expired:      expired,
		Certificates: certificates,
		Message:      fmt.Sprintf("Certificate check completed: %d total, %d valid, %d expiring, %d expired",
			total, valid, expiringSoon, expired),
	}
}

// ToJSON converts a response to JSON
func (r *Response) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToJSON converts a certificate response to JSON
func (r *CertificateResponse) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToJSON converts a deployment response to JSON
func (r *DeploymentResponse) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToJSON converts a list response to JSON
func (r *ListResponse) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToJSON converts a check response to JSON
func (r *CheckResponse) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// ToString returns the JSON string representation of a response
func (r *Response) ToString() (string, error) {
	data, err := r.ToJSON()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// APIError represents an API error that can be returned
type APIError struct {
	Code    string
	Message string
	Details  string
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// NewAPIError creates a new API error
func NewAPIError(code, message, details string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Details:  details,
	}
}

// Common error codes
const (
	ErrCodeInvalidInput    = "InvalidInput"
	ErrCodeNotFound       = "NotFound"
	ErrCodeInternalError  = "InternalError"
	ErrCodeAuthFailed    = "AuthenticationFailed"
	ErrRateLimitExceeded = "RateLimitExceeded"
)

// Errors
var (
	ErrInvalidDomain    = NewAPIError(ErrCodeInvalidInput, "Invalid domain format", "")
	ErrInvalidResource  = NewAPIError(ErrCodeInvalidInput, "Invalid resource type", "")
	ErrCertNotFound    = NewAPIError(ErrCodeNotFound, "Certificate not found", "")
	ErrDomainNotFound  = NewAPIError(ErrCodeNotFound, "Domain not found", "")
	ErrACMEFailed     = NewAPIError(ErrCodeInternalError, "ACME operation failed", "")
	ErrDNSFailed      = NewAPIError(ErrCodeInternalError, "DNS operation failed", "")
)

// NewRenewalUpdateSuccess creates a renewal success response with update method
func NewRenewalUpdateSuccess(domain string, domains []string, certID string, deployRecordID string) *CertificateResponse {
	return &CertificateResponse{
		Success:  true,
		Domain:   domain,
		Domains:  domains,
		CertID:   certID,  // Preserved ID
		Message:  fmt.Sprintf("Certificate renewed successfully (DeployRecordId: %s)", deployRecordID),
	}
}

// NewRenewalFallback creates a renewal fallback response
func NewRenewalFallback(domain string, certID string, errorMsg string) *CertificateResponse {
	return &CertificateResponse{
		Success:  true,
		Domain:   domain,
		CertID:   certID,  // New ID
		Message:  fmt.Sprintf("Certificate renewed using fallback method: %s", errorMsg),
	}
}
