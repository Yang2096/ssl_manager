package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yang/ssl-manager/pkg/config"
	"github.com/yang/ssl-manager/pkg/handler"
)

// Version is set during build
var Version = "dev"

// CLI represents command-line interface
type CLI struct {
	cfg    *config.Config
	handler *handler.CertificateHandler
}

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Handler     func(*CLI, []string) error
	Args        []string
}

func main() {
	log.SetFlags(log.LstdFlags)

	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Create handler
	h, err := handler.NewCertificateHandler(cfg)
	if err != nil {
		log.Fatalf("Failed to create handler: %v", err)
	}

	cli := &CLI{
		cfg:    cfg,
		handler: h,
	}

	// Execute command
	commandName := os.Args[1]
	args := os.Args[2:]

	switch commandName {
	case "issue":
		cli.issueCommand(args, false)
	case "issue-local":
		cli.issueLocalCommand(args)
	case "renew":
		cli.renewCommand(args)
	case "list":
		cli.listCommand(args)
	case "check":
		cli.checkCommand(args)
	case "upload":
		cli.uploadCommand(args)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", commandName)
		printHelp()
		os.Exit(1)
	}
}

func (c *CLI) issueCommand(args []string, staging bool) {
	if len(args) < 1 {
		fmt.Println("Usage: ssl-manager issue <domain>")
		os.Exit(1)
	}

	domain := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := c.handler.IssueCertificate(ctx, domain, nil)
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	if !result.Success {
		log.Fatalf("Certificate issuance failed: %s", result.Message)
	}

	fmt.Printf("Certificate issued successfully!\n")
	fmt.Printf("Domain: %s\n", result.Domain)
	fmt.Printf("Certificate ID: %s\n", result.CertID)
	fmt.Printf("Expires at: %s\n", result.ExpiresAt)
}

func (c *CLI) issueLocalCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ssl-manager issue-local <domain> [--email <email>]")
		os.Exit(1)
	}

	domain := args[0]
	email := ""
	for i := 1; i < len(args)-1; i += 2 {
		if args[i] == "--email" && i+1 < len(args) {
			email = args[i+1]
		}
	}

	if email == "" {
		email = c.cfg.ACMEAccountEmail
		if email == "" {
			email = "admin@example.com"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := c.handler.IssueCertificateLocal(ctx, domain, nil)
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	if !result.Success {
		log.Fatalf("Certificate issuance failed: %s", result.Message)
	}

	fmt.Printf("Certificate issued successfully locally!\n")
	fmt.Printf("Domain: %s\n", result.Domain)
	fmt.Printf("Certificate path: %s\n", result.CertPath)
	fmt.Printf("Private key path: %s\n", result.KeyPath)
}

func (c *CLI) renewCommand(args []string) {
	force := false
	if len(args) > 0 && args[0] == "--force" {
		force = true
		args = args[1:]
	}

	if len(args) < 1 {
		fmt.Println("Usage: ssl-manager renew <domain> [--force]")
		os.Exit(1)
	}

	domain := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := c.handler.RenewCertificate(ctx, domain, force)
	if err != nil {
		log.Fatalf("Failed to renew certificate: %v", err)
	}

	if !result.Success {
		log.Fatalf("Certificate renewal failed: %s", result.Message)
	}

	fmt.Printf("Certificate renewed successfully!\n")
	fmt.Printf("Domain: %s\n", result.Domain)
	if result.RemainingDays > 0 {
		fmt.Printf("Remaining days: %d\n", result.RemainingDays)
	}
}

func (c *CLI) listCommand(args []string) {
	searchDomain := ""
	if len(args) > 0 {
		searchDomain = args[0]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	result, err := c.handler.ListCertificates(ctx, searchDomain)
	if err != nil {
		log.Fatalf("Failed to list certificates: %v", err)
	}

	if result.Total == 0 {
		fmt.Println("No certificates found.")
		return
	}

	fmt.Printf("Found %d certificate(s)\n\n", result.Total)

	// Type assert for certificate list ([]map[string]interface{})
	certList, ok := result.Items.([]map[string]interface{})
	if !ok {
		log.Fatalf("Invalid certificate list format")
	}

	for i, cert := range certList {
		domain := getStringVal(cert, "Domain")
		certID := getStringVal(cert, "CertificateId")
		statusName := getStringVal(cert, "StatusName")
		isWildcard := getBoolVal(cert, "IsWildcard")
		isDv := getBoolVal(cert, "IsDv")
		isVip := getBoolVal(cert, "IsVip")
		certEndTime := getStringVal(cert, "CertEndTime")
		alias := getStringVal(cert, "Alias")
		remainingDays := 0
		if v, ok := cert["RemainingDays"].(int); ok {
			remainingDays = v
		}

		fmt.Printf("[%d] %s\n", i+1, domain)
		fmt.Printf("    Certificate ID: %s\n", certID)
		fmt.Printf("    Status: %s\n", statusName)

		// Show certificate type
		var types []string
		if isWildcard {
			types = append(types, "Wildcard")
		}
		if isDv {
			types = append(types, "DV")
		}
		if isVip {
			types = append(types, "VIP")
		}
		if len(types) > 0 {
			fmt.Printf("    Type: %s\n", strings.Join(types, ", "))
		}

		// Show expiry information
		if remainingDays > 0 {
			fmt.Printf("    Expires: %s (%d days remaining)\n", certEndTime, remainingDays)
		} else if remainingDays == 0 && certEndTime != "" {
			fmt.Printf("    Expires: %s (expired)\n", certEndTime)
		}

		if alias != "" {
			fmt.Printf("    Alias: %s\n", alias)
		}
		fmt.Println()
	}
}

// Helper functions for CLI
func getStringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBoolVal(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func (c *CLI) checkCommand(args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	checkResult, err := c.handler.CheckAndRenew(ctx)
	if err != nil {
		log.Fatalf("Failed to check certificates: %v", err)
	}

	if checkResult == nil {
		log.Fatalf("Check result is nil")
	}

	fmt.Printf("Certificate check completed!\n")
	fmt.Printf("Total: %d\n", checkResult.Total)
	fmt.Printf("Valid: %d\n", checkResult.Valid)
	fmt.Printf("Expiring soon: %d\n", checkResult.ExpiringSoon)
	fmt.Printf("Expired: %d\n", checkResult.Expired)
}

func (c *CLI) uploadCommand(args []string) {
	certDir := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--cert-dir" && i+1 < len(args) {
			certDir = args[i+1]
			i++
		}
	}

	if len(args) < 1 {
		fmt.Println("Usage: ssl-manager upload <domain> [--cert-dir <path>]")
		os.Exit(1)
	}

	domain := args[0]

	if certDir == "" {
		certDir = "./certs/" + domain
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := c.handler.UploadCertificate(ctx, domain, certDir)
	if err != nil {
		log.Fatalf("Failed to upload certificate: %v", err)
	}

	if !result.Success {
		log.Fatalf("Certificate upload failed: %s", result.Message)
	}

	fmt.Printf("Certificate uploaded successfully!\n")
	fmt.Printf("Domain: %s\n", result.Domain)
	fmt.Printf("Certificate ID: %s\n", result.CertID)
}

func printHelp() {
	fmt.Printf("SSL Manager v%s\n", Version)
	fmt.Println("Usage: ssl-manager <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  issue       Issue a new certificate and upload to Tencent Cloud SSL")
	fmt.Println("  issue-local Issue a certificate locally (without uploading)")
	fmt.Println("  renew       Renew a certificate")
	fmt.Println("  list        List certificates")
	fmt.Println("  check       Check and auto-renew expiring certificates")
	fmt.Println("  upload      Upload an existing certificate to Tencent Cloud")
	fmt.Println("  help        Show this help message")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  TENCENT_SECRET_ID        Tencent Cloud Secret ID (required)")
	fmt.Println("  TENCENT_SECRET_KEY        Tencent Cloud Secret Key (required)")
	fmt.Println("  TENCENT_REGION            Tencent Cloud region (default: ap-guangzhou)")
	fmt.Println("  ACME_ACCOUNT_EMAIL        ACME account email (default: admin@example.com)")
	fmt.Println("  ACME_HOME_DIR            ACME home directory (default: /tmp/acme)")
	fmt.Println("  ACME_DNS_PROPAGATION     DNS propagation wait time in seconds (default: 60)")
	fmt.Println("  ACME_STAGING              Use Let's Encrypt staging (default: false)")
	fmt.Println("  CERT_EXPIRY_WARNING_DAYS   Certificate expiry warning days (default: 30)")
	fmt.Println("  NOTIFY_ENABLED             Enable webhook notifications (default: false)")
	fmt.Println("  NOTIFY_WEBHOOK             Webhook URL for notifications")
}
