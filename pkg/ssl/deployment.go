package ssl

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// DeploymentOperations handles certificate deployment operations
type DeploymentOperations struct {
	client *Client
}

// NewDeploymentOperations creates a new deployment operations handler
func NewDeploymentOperations(client *Client) *DeploymentOperations {
	return &DeploymentOperations{client: client}
}

// DeployResult represents the result of a deployment operation
type DeployResult struct {
	DeploymentID string `json:"deployment_id"`
	Status       string `json:"status"`
	Success      bool   `json:"success"`
	Message      string `json:"message"`
}

// Deploy deploys a certificate to a cloud resource
func (d *DeploymentOperations) Deploy(ctx context.Context, certID, resourceType string, resourceIDs []string, domain string) (*DeployResult, error) {
	log.Printf("Deploying certificate %s to %s resources: %v", certID, resourceType, resourceIDs)

	// Validate resource type
	if !isValidResourceType(resourceType) {
		return &DeployResult{
			Success: false,
			Message: fmt.Sprintf("Unsupported resource type: %s", resourceType),
		}, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	request := ssl.NewDeployCertificateInstanceRequest()
	request.CertificateId = common.StringPtr(certID)
	request.ResourceType = common.StringPtr(resourceType)
	request.InstanceIdList = common.StringPtrs(resourceIDs)

	response, err := d.client.client.DeployCertificateInstance(request)
	if err != nil {
		return &DeployResult{
			Success: false,
			Message: err.Error(),
		}, fmt.Errorf("failed to deploy certificate: %w", err)
	}

	deploymentID := ""
	if response.Response.RequestId != nil {
		deploymentID = *response.Response.RequestId
	}

	status := "success"

	log.Printf("Deployment initiated: ID=%s, Status=%s", deploymentID, status)

	return &DeployResult{
		DeploymentID: deploymentID,
		Status:       status,
		Success:      true,
		Message:      "Deployment initiated successfully",
	}, nil
}

// DeployToCDN deploys a certificate to CDN
func (d *DeploymentOperations) DeployToCDN(ctx context.Context, certID, domain string) (*DeployResult, error) {
	log.Printf("Deploying certificate %s to CDN for domain %s", certID, domain)
	return d.Deploy(ctx, certID, "cdn", []string{domain}, domain)
}

// DeployToCLB deploys a certificate to Cloud Load Balancer
func (d *DeploymentOperations) DeployToCLB(ctx context.Context, certID string, listenerIDs []string) (*DeployResult, error) {
	log.Printf("Deploying certificate %s to CLB listeners: %v", certID, listenerIDs)
	return d.Deploy(ctx, certID, "clb", listenerIDs, "")
}

// DeployToAPIGateway deploys a certificate to API Gateway
func (d *DeploymentOperations) DeployToAPIGateway(ctx context.Context, certID string, apiIDs []string) (*DeployResult, error) {
	log.Printf("Deploying certificate %s to API Gateway: %v", certID, apiIDs)
	return d.Deploy(ctx, certID, "apigateway", apiIDs, "")
}

// DeployToSCF deploys a certificate to Serverless Cloud Function custom domain
func (d *DeploymentOperations) DeployToSCF(ctx context.Context, certID string, domains []string) (*DeployResult, error) {
	log.Printf("Deploying certificate %s to SCF custom domains: %v", certID, domains)
	return d.Deploy(ctx, certID, "scf", domains, "")
}

// ReplaceCertificate replaces a certificate on resources
// certID is the NEW certificate ID to deploy to resources
func (d *DeploymentOperations) ReplaceCertificate(ctx context.Context, certID, resourceType string, resourceIDs []string) (*DeployResult, error) {
	log.Printf("Replacing certificate for %s resources: %v", resourceType, resourceIDs)

	if !isValidResourceType(resourceType) {
		return &DeployResult{
			Success: false,
			Message: fmt.Sprintf("Unsupported resource type: %s", resourceType),
		}, fmt.Errorf("unsupported resource type: %s", resourceType)
	}

	// Note: Go SDK UpdateCertificateInstanceRequest has different fields than Python SDK
	// It uses OldCertificateId + new cert content OR CertificateId for new cert ID
	// Since we have the new certificate ID, use CertificateId with ResourceTypes
	request := ssl.NewUpdateCertificateInstanceRequest()
	request.CertificateId = common.StringPtr(certID) // New certificate ID
	request.ResourceTypes = common.StringPtrs([]string{resourceType})

	_, err := d.client.client.UpdateCertificateInstance(request)
	if err != nil {
		return &DeployResult{
			Success: false,
			Message: err.Error(),
		}, fmt.Errorf("failed to replace certificate: %w", err)
	}

	return &DeployResult{
		Status:  "success",
		Success: true,
		Message: "Certificate replaced successfully",
	}, nil
}

// BatchDeploymentResult represents the result of a batch deployment
type BatchDeploymentResult struct {
	Total      int          `json:"total"`
	Success    int          `json:"success"`
	Failed     int          `json:"failed"`
	Results    []DeployResult `json:"results"`
}

// BatchDeploy deploys a certificate to multiple resources
func (d *DeploymentOperations) BatchDeploy(ctx context.Context, certID string, deployments []DeploymentTarget) *BatchDeploymentResult {
	result := &BatchDeploymentResult{
		Total:   len(deployments),
		Results: make([]DeployResult, 0),
	}

	for _, target := range deployments {
		deployResult, err := d.Deploy(ctx, certID, target.ResourceType, target.ResourceIDs, target.Domain)
		if err != nil {
			result.Failed++
			if deployResult == nil {
				deployResult = &DeployResult{
					Success: false,
					Message: err.Error(),
				}
			}
			result.Results = append(result.Results, *deployResult)
		} else {
			result.Success++
			result.Results = append(result.Results, *deployResult)
		}
	}

	return result
}

// DeploymentTarget represents a target for certificate deployment
type DeploymentTarget struct {
	ResourceType string   `json:"resource_type"`
	ResourceIDs  []string `json:"resource_ids"`
	Domain       string   `json:"domain,omitempty"`
}

// isValidResourceType checks if a resource type is supported
func isValidResourceType(resourceType string) bool {
	validTypes := []string{
		"clb", "cdn", "waf", "live", "ddos", "teo",
		"apigateway", "vod", "tke", "tcb", "tse", "cos", "scf",
	}

	for _, t := range validTypes {
		if t == strings.ToLower(resourceType) {
			return true
		}
	}
	return false
}

// GetSupportedResourceTypes returns a list of supported resource types
func GetSupportedResourceTypes() []string {
	return []string{
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
}

// GetResourceTypeName returns a human-readable name for a resource type
func GetResourceTypeName(resourceType string) string {
	names := map[string]string{
		"clb":       "Cloud Load Balancer",
		"cdn":       "Content Delivery Network",
		"waf":       "Web Application Firewall",
		"live":      "Live Streaming",
		"ddos":      "DDoS Protection",
		"teo":       "EdgeOne",
		"apigateway": "API Gateway",
		"vod":       "Video on Demand",
		"tke":       "Tencent Kubernetes Engine",
		"tcb":       "CloudBase",
		"tse":       "Tencent微服务引擎",
		"cos":       "Cloud Object Storage",
		"scf":       "Serverless Cloud Function",
	}

	if name, ok := names[strings.ToLower(resourceType)]; ok {
		return name
	}
	return resourceType
}
