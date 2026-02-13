package ssl

import (
	"context"
	"fmt"
	"log"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	scf "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/scf/v20180416"
)

// SCFCustomDomainHandler handles SCF custom domain certificate operations
type SCFCustomDomainHandler struct {
	client  *scf.Client
	secretID string
	secretKey string
	region   string
}

// NewSCFCustomDomainHandler creates a new SCF custom domain handler
func NewSCFCustomDomainHandler(secretID, secretKey, region string) (*SCFCustomDomainHandler, error) {
	credential := common.NewCredential(secretID, secretKey)

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "scf.tencentcloudapi.com"

	client, err := scf.NewClient(credential, region, cpf)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCF client: %w", err)
	}

	return &SCFCustomDomainHandler{
		client:   client,
		secretID: secretID,
		secretKey: secretKey,
		region:    region,
	}, nil
}

// UpdateDomainCertificate updates HTTPS certificate for an SCF custom domain
func (h *SCFCustomDomainHandler) UpdateDomainCertificate(ctx context.Context, namespace, domain, certID string) error {
	log.Printf("Updating SCF custom domain certificate: %s (namespace: %s, cert: %s)", domain, namespace, certID)

	request := scf.NewUpdateCustomDomainRequest()
	request.Domain = common.StringPtr(domain)

	// Set certificate configuration
	certConfig := &scf.CertConf{}
	certConfig.CertificateId = common.StringPtr(certID)
	request.CertConfig = certConfig

	_, err := h.client.UpdateCustomDomain(request)
	if err != nil {
		return fmt.Errorf("failed to update SCF custom domain certificate: %w", err)
	}

	log.Printf("SCF custom domain certificate updated: %s", domain)
	return nil
}

// CustomDomainInfo represents SCF custom domain information
type CustomDomainInfo struct {
	Domain  string `json:"domain"`
	CertID  string `json:"cert_id"`
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
}

// GetCustomDomain retrieves information about an SCF custom domain
func (h *SCFCustomDomainHandler) GetCustomDomain(ctx context.Context, namespace, domain string) (*CustomDomainInfo, error) {
	log.Printf("Getting SCF custom domain info: %s (namespace: %s)", domain, namespace)

	request := scf.NewGetCustomDomainRequest()
	request.Domain = common.StringPtr(domain)

	response, err := h.client.GetCustomDomain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to get SCF custom domain: %w", err)
	}

	info := &CustomDomainInfo{
		Domain:  domain,
		Protocol: "",
		Status:   "",
	}

	if response.Response != nil {
		r := response.Response
		if r.Domain != nil {
			info.Domain = *r.Domain
		}
		if r.Protocol != nil {
			info.Protocol = *r.Protocol
		}
		if r.CertConfig != nil && r.CertConfig.CertificateId != nil {
			info.CertID = *r.CertConfig.CertificateId
		}
	}

	return info, nil
}

// ListCustomDomains lists all custom domains in a namespace
func (h *SCFCustomDomainHandler) ListCustomDomains(ctx context.Context, namespace string) ([]CustomDomainInfo, error) {
	log.Printf("Listing SCF custom domains in namespace: %s", namespace)

	request := scf.NewListCustomDomainsRequest()
	request.Limit = common.Uint64Ptr(100)

	response, err := h.client.ListCustomDomains(request)
	if err != nil {
		return nil, fmt.Errorf("failed to list SCF custom domains: %w", err)
	}

	domains := make([]CustomDomainInfo, 0)
	if response.Response != nil && response.Response.Domains != nil {
		for _, cd := range response.Response.Domains {
			info := CustomDomainInfo{
				Domain:  getStringPtr(cd.Domain),
				Protocol: getStringPtr(cd.Protocol),
			}
			domains = append(domains, info)
		}
	}

	return domains, nil
}

// SetDomainProtocol sets protocol (HTTP/HTTPS) for a custom domain
func (h *SCFCustomDomainHandler) SetDomainProtocol(ctx context.Context, namespace, domain, protocol string) error {
	log.Printf("Setting SCF custom domain protocol: %s to %s", domain, protocol)

	request := scf.NewUpdateCustomDomainRequest()
	request.Domain = common.StringPtr(domain)
	request.Protocol = common.StringPtr(protocol)

	// If setting to HTTPS, we need a certificate
	if protocol == "HTTPS" || protocol == "https" {
		// Keep existing cert or set to empty
		certConfig := &scf.CertConf{}
		request.CertConfig = certConfig
	}

	_, err := h.client.UpdateCustomDomain(request)
	if err != nil {
		return fmt.Errorf("failed to set SCF custom domain protocol: %w", err)
	}

	log.Printf("SCF custom domain protocol updated: %s to %s", domain, protocol)
	return nil
}

func getStringPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
