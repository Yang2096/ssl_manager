package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Level represents the notification level
type Level string

const (
	LevelInfo     Level = "info"
	LevelWarning  Level = "warning"
	LevelError   Level = "error"
	LevelCritical Level = "critical"
)

// WebhookNotifier sends notifications via webhook
type WebhookNotifier struct {
	webhookURL string
	enabled    bool
	httpClient *http.Client
}

// NotificationPayload represents a webhook notification payload
type NotificationPayload struct {
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	Level     Level                  `json:"level"`
	Timestamp string                 `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string, enabled bool) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		enabled:    enabled,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends a notification
func (n *WebhookNotifier) Send(ctx context.Context, title, message string, level Level, data map[string]interface{}) error {
	if !n.enabled || n.webhookURL == "" {
		log.Printf("Notification disabled or webhook not configured")
		return nil
	}

	payload := NotificationPayload{
		Title:     title,
		Message:   message,
		Level:     level,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      data,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal notification payload: %w", err)
	}

	log.Printf("Sending webhook notification to %s: %s", n.webhookURL, string(jsonData))

	req, err := http.NewRequestWithContext(ctx, "POST", n.webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	log.Printf("Webhook notification sent successfully: %s", title)
	return nil
}

// NotifySuccess sends a success notification
func (n *WebhookNotifier) NotifySuccess(ctx context.Context, domain, action, certID string) error {
	return n.Send(ctx,
		fmt.Sprintf("Certificate %s Success", action),
		fmt.Sprintf("Certificate for %s has been %sed successfully", domain, action),
		LevelInfo,
		map[string]interface{}{
			"domain":  domain,
			"action":  action,
			"cert_id": certID,
		},
	)
}

// NotifyFailure sends a failure notification
func (n *WebhookNotifier) NotifyFailure(ctx context.Context, domain, action, errorMsg string) error {
	return n.Send(ctx,
		fmt.Sprintf("Certificate %s Failed", action),
		fmt.Sprintf("Failed to %s certificate for %s: %s", action, domain, errorMsg),
		LevelError,
		map[string]interface{}{
			"domain":  domain,
			"action":  action,
			"error":   errorMsg,
		},
	)
}

// NotifyRenewalSuccess sends a renewal success notification
func (n *WebhookNotifier) NotifyRenewalSuccess(ctx context.Context, domain, oldCertID, newCertID string) error {
	return n.Send(ctx,
		"Certificate Renewal Success",
		fmt.Sprintf("Certificate for %s has been renewed successfully", domain),
		LevelInfo,
		map[string]interface{}{
			"domain":      domain,
			"old_cert_id": oldCertID,
			"new_cert_id": newCertID,
		},
	)
}

// NotifyExpiringSoon sends a warning for certificates expiring soon
func (n *WebhookNotifier) NotifyExpiringSoon(ctx context.Context, domain string, remainingDays int, certID string) error {
	level := LevelWarning
	if remainingDays <= 7 {
		level = LevelCritical
	}

	return n.Send(ctx,
		"Certificate Expiring Soon",
		fmt.Sprintf("Certificate for %s expires in %d days", domain, remainingDays),
		level,
		map[string]interface{}{
			"domain":         domain,
			"remaining_days": remainingDays,
			"cert_id":        certID,
		},
	)
}

// NotifyDeployment sends a deployment notification
func (n *WebhookNotifier) NotifyDeployment(ctx context.Context, domain, resourceType, deploymentID string, success bool) error {
	action := "deployed"
	level := LevelInfo
	title := "Certificate Deployment Success"

	if !success {
		action = "deployment failed"
		level = LevelError
		title = "Certificate Deployment Failed"
	}

	return n.Send(ctx,
		title,
		fmt.Sprintf("Certificate %s for %s to %s", action, domain, resourceType),
		level,
		map[string]interface{}{
			"domain":        domain,
			"resource_type": resourceType,
			"deployment_id": deploymentID,
		},
	)
}

// NotifyCheckResults sends a summary of certificate check results
func (n *WebhookNotifier) NotifyCheckResults(ctx context.Context, total, expiring, expired int) error {
	message := fmt.Sprintf("Certificate check completed: %d total, %d expiring, %d expired", total, expiring, expired)
	level := LevelInfo

	if expired > 0 {
		level = LevelCritical
	} else if expiring > 0 {
		level = LevelWarning
	}

	return n.Send(ctx,
		"Certificate Check Results",
		message,
		level,
		map[string]interface{}{
			"total":     total,
			"expiring":   expiring,
			"expired":    expired,
		},
	)
}

// IsEnabled returns whether the notifier is enabled
func (n *WebhookNotifier) IsEnabled() bool {
	return n.enabled && n.webhookURL != ""
}

// GetWebhookURL returns the webhook URL
func (n *WebhookNotifier) GetWebhookURL() string {
	return n.webhookURL
}

// SetEnabled enables or disables the notifier
func (n *WebhookNotifier) SetEnabled(enabled bool) {
	n.enabled = enabled
}
