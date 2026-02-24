package qiniu

// CertificateInfo represents a certificate in Qiniu
type CertificateInfo struct {
	CertID           string   `json:"certId"`
	Name             string   `json:"name"`
	UID              int64    `json:"uid"`
	CommonName       string   `json:"common_name"`
	DNSNames         []string `json:"dnsnames"`
	CreateTime       int64    `json:"create_time"`
	NotBefore        int64    `json:"not_before"`
	NotAfter         int64    `json:"not_after"`
	ProductType      string   `json:"product_type"`  // single, multi, wildcard
	CertType         string   `json:"cert_type"`     // DV, OV, EV
	Encrypt          string   `json:"encrypt"`       // RSA, ECC
	Enable           bool     `json:"enable"`
	AutoRenew        bool     `json:"auto_renew"`
	Renewable        bool     `json:"renewable"`
}

// ListCertificatesResponse represents the response from listing certificates
type ListCertificatesResponse struct {
	Marker string            `json:"marker"`
	Certs  []CertificateInfo `json:"certs"`
}

// UploadCertificateRequest represents a certificate upload request
type UploadCertificateRequest struct {
	Name       string `json:"name"`
	CommonName string `json:"commonName"`
	Pri        string `json:"pri"` // Private key
	Ca         string `json:"ca"`  // Certificate chain
}

// UploadCertificateResponse represents the response from uploading a certificate
type UploadCertificateResponse struct {
	CertID string `json:"certId"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"error"`
}
