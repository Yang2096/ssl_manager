package qiniu

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

const (
	// CertificatesPath is the API path for certificate operations
	CertificatesPath = "/sslcert"
	// DefaultListLimit is the default limit for listing certificates
	DefaultListLimit = 100
)

// CertificateOperations provides certificate-related operations
type CertificateOperations struct {
	client *Client
}

// NewCertificateOperations creates a new certificate operations instance
func NewCertificateOperations(client *Client) *CertificateOperations {
	return &CertificateOperations{client: client}
}

// Upload uploads a certificate to Qiniu
func (c *Client) Upload(ctx context.Context, req *UploadCertificateRequest) (string, error) {
	respBody, err := c.doRequest(ctx, "POST", CertificatesPath, req)
	if err != nil {
		return "", err
	}

	var result UploadCertificateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("[Qiniu] Certificate uploaded successfully: %s", result.CertID)
	return result.CertID, nil
}

// list lists certificates with optional marker and limit (internal method)
func (c *Client) list(ctx context.Context, marker string, limit int) (*ListCertificatesResponse, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}

	path := fmt.Sprintf("%s?Limit=%d", CertificatesPath, limit)
	if marker != "" {
		path += fmt.Sprintf("&Marker=%s", marker)
	}

	respBody, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result ListCertificatesResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// IsDomainOnQiniu checks if a domain is being used on Qiniu
// by checking if there's an existing certificate for this domain
func (c *Client) IsDomainOnQiniu(ctx context.Context, domain string) (bool, error) {
	certs, err := c.GetCertificatesByDomain(ctx, domain)
	if err != nil {
		return false, err
	}
	return len(certs) > 0, nil
}

// Delete deletes a certificate by ID
func (c *Client) Delete(ctx context.Context, certID string) error {
	path := fmt.Sprintf("%s/%s", CertificatesPath, certID)

	_, err := c.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		// Log but don't fail if certificate doesn't exist
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404") {
			log.Printf("[Qiniu] Certificate %s not found, may have been already deleted", certID)
			return nil
		}
		return err
	}

	log.Printf("[Qiniu] Certificate deleted: %s", certID)
	return nil
}

// UploadCertificate uploads a certificate to Qiniu (convenience method)
func (c *Client) UploadCertificate(ctx context.Context, name, commonName, privateKey, certChain string) (string, error) {
	req := &UploadCertificateRequest{
		Name:       name,
		CommonName: commonName,
		Pri:        privateKey,
		Ca:         certChain,
	}
	return c.Upload(ctx, req)
}

// GetCertificatesByDomain gets all certificates for a domain
func (c *Client) GetCertificatesByDomain(ctx context.Context, domain string) ([]CertificateInfo, error) {
	allCerts, err := c.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}

	var matchedCerts []CertificateInfo
	for _, cert := range allCerts {
		// Check CommonName
		if cert.CommonName == domain {
			matchedCerts = append(matchedCerts, cert)
			continue
		}
		// Check DNSNames
		for _, dnsName := range cert.DNSNames {
			if dnsName == domain {
				matchedCerts = append(matchedCerts, cert)
				break
			}
		}
	}

	return matchedCerts, nil
}

// ListCertificates lists all certificates (convenience method)
func (c *Client) ListCertificates(ctx context.Context) ([]CertificateInfo, error) {
	var allCerts []CertificateInfo
	marker := ""

	for {
		result, err := c.list(ctx, marker, DefaultListLimit)
		if err != nil {
			return nil, err
		}

		allCerts = append(allCerts, result.Certs...)

		// Qiniu API may return marker as the Limit value (e.g., "100") when there's no more data
		// So we also check if the returned certs count is 0 or less than the requested limit
		if result.Marker == "" || len(result.Certs) == 0 || len(result.Certs) < DefaultListLimit {
			break
		}
		marker = result.Marker
	}

	return allCerts, nil
}
