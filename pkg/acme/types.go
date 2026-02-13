package acme

import "time"

// CertificateResult represents the result of a certificate request
type CertificateResult struct {
	Success   bool      `json:"success"`
	Domain    string    `json:"domain"`
	Domains   []string  `json:"domains"`
	CertPath  string    `json:"cert_path,omitempty"`
	KeyPath   string    `json:"key_path,omitempty"`
	CSRPath   string    `json:"csr_path,omitempty"`
	CertPEM   string    `json:"cert_pem,omitempty"`
	KeyPEM    string    `json:"key_pem,omitempty"`
	CSRPEM    string    `json:"csr_pem,omitempty"`
	Message   string    `json:"message"`
	Error     string    `json:"error,omitempty"`
	IssuedAt  time.Time `json:"issued_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// DNSRecord represents a DNS record for ACME challenge
type DNSRecord struct {
	RecordName  string `json:"record_name"`
	RecordValue string `json:"record_value"`
	Domain      string `json:"domain"`
	SubDomain   string `json:"sub_domain"`
}

// AccountInfo represents ACME account information
type AccountInfo struct {
	Email        string   `json:"email"`
	Registration string   `json:"registration_uri,omitempty"`
	Location     string   `json:"location,omitempty"`
	Status       string   `json:"status,omitempty"`
	Contact      []string `json:"contact,omitempty"`
}

// OrderStatus represents the status of an ACME order
type OrderStatus string

const (
	OrderStatusPending    OrderStatus = "pending"
	OrderStatusReady      OrderStatus = "ready"
	OrderStatusProcessing OrderStatus = "processing"
	OrderStatusValid      OrderStatus = "valid"
	OrderStatusInvalid    OrderStatus = "invalid"
)

// AuthorizationStatus represents the status of an ACME authorization
type AuthorizationStatus string

const (
	AuthStatusPending    AuthorizationStatus = "pending"
	AuthStatusValid      AuthorizationStatus = "valid"
	AuthStatusInvalid    AuthorizationStatus = "invalid"
	AuthStatusProcessing AuthorizationStatus = "processing"
	AuthStatusDeactivated AuthorizationStatus = "deactivated"
	AuthStatusExpired    AuthorizationStatus = "expired"
	AuthStatusRevoked    AuthorizationStatus = "revoked"
)
