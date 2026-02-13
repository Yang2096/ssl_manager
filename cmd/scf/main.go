package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/tencentyun/scf-go-lib/cloudfunction"
	"github.com/yang/ssl-manager/pkg/config"
	"github.com/yang/ssl-manager/pkg/handler"
	"github.com/yang/ssl-manager/pkg/response"
)

// TimerEvent represents a SCF timer trigger event
type TimerEvent struct {
	Type        string `json:"Type"`
	TriggerName string `json:"TriggerName"`
	Time        string `json:"Time"`
	Message     string `json:"Message"`
}

// Version is set during build
var Version = "dev"

// Handler is the SCF entry point
func Handler(ctx context.Context, event interface{}) (interface{}, error) {
	log.Printf("SCF invocation started. Version: %s", Version)
	log.Printf("Received event: %+v", event)

	// Parse Timer event
	var timerEvent TimerEvent
	switch e := event.(type) {
	case TimerEvent:
		timerEvent = e
	case map[string]interface{}:
		// JSON unmarshaled event
		if eventType, ok := e["Type"].(string); ok && eventType == "Timer" {
			timerEvent = TimerEvent{
				// Type:        eventType,
				TriggerName: getStringFromMap(e, "TriggerName"),
				// Time:        getStringFromMap(e, "Time"),
				Message:     getStringFromMap(e, "Message"),
			}
		} else {
			return response.NewError("InvalidEvent", "Event Type must be 'Timer'", ""), nil
		}
	default:
		return response.NewError("InvalidEvent", fmt.Sprintf("Unknown event type: %T", event), ""), nil
	}

	log.Printf("Timer trigger: %s, Message: %s", timerEvent.TriggerName, timerEvent.Message)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return response.NewError("ConfigError", err.Error(), ""), nil
	}

	if err := cfg.Validate(); err != nil {
		log.Printf("Configuration validation failed: %v", err)
		return response.NewError("ValidationError", err.Error(), ""), nil
	}

	// Create certificate handler
	certHandler, err := handler.NewCertificateHandler(cfg)
	if err != nil {
		log.Printf("Failed to create certificate handler: %v", err)
		return response.NewError("HandlerError", err.Error(), ""), nil
	}

	// Parse action from Message field
	action, params := parseActionMessage(timerEvent.Message)
	log.Printf("Processing action: %s", action)

	// Process the action
	result := processAction(ctx, certHandler, action, params)
	return result, nil
}

// parseActionMessage parses action and parameters from Message field
// Message format examples:
//   - "check" -> action=check, params={}
//   - "renew:example.com" -> action=renew, params={domain: example.com}
//   - "renew:example.com::true" -> action=renew, params={domain: example.com, force: true}
//   - "issue:example.com:true" -> action=issue, params={domain: example.com, staging: true}
func parseActionMessage(message string) (string, map[string]interface{}) {
	if message == "" {
		return "check", nil
	}

	parts := strings.Split(message, ":")
	action := parts[0]
	params := make(map[string]interface{})

	if len(parts) > 1 && parts[1] != "" {
		params["domain"] = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		params["staging"] = parts[2] == "true"
	}
	if len(parts) > 3 && parts[3] != "" {
		params["force"] = parts[3] == "true"
	}

	return action, params
}

// processAction processes the action and returns a response
func processAction(ctx context.Context, h *handler.CertificateHandler, action string, params map[string]interface{}) interface{} {
	switch action {
	case "check":
		result, _ := h.CheckAndRenew(ctx)
		return result

	case "renew":
		domain := getStringFromMap(params, "domain")
		if domain == "" {
			return response.NewError("InvalidInput", "domain is required for renew action", "")
		}
		force := getBoolFromMap(params, "force", false)
		result, _ := h.RenewCertificate(ctx, domain, force)
		return result

	case "issue":
		domain := getStringFromMap(params, "domain")
		if domain == "" {
			return response.NewError("InvalidInput", "domain is required for issue action", "")
		}
		result, _ := h.IssueCertificate(ctx, domain, nil)
		return result

	case "list":
		domain := getStringFromMap(params, "domain")
		result, _ := h.ListCertificates(ctx, domain)
		return result

	default:
		return response.NewError("InvalidAction", fmt.Sprintf("Unknown action: %s", action), "")
	}
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolFromMap(m map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
		if str, ok := val.(string); ok {
			return str == "true" || str == "1"
		}
	}
	return defaultValue
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	cloudfunction.Start(Handler)
}
