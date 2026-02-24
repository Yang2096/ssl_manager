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
	"github.com/yang/ssl-manager/pkg/qiniu"
	"github.com/yang/ssl-manager/pkg/ssl"
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
	case "list-qiniu":
		cli.listQiniuCommand(args)
	case "delete-qiniu":
		cli.deleteQiniuCommand(args)
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
	if len(args) < 1 {
		fmt.Println("Usage: ssl-manager renew <domain>")
		os.Exit(1)
	}

	domain := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := c.handler.RenewCertificate(ctx, domain)
	if err != nil {
		log.Fatalf("Failed to renew certificate: %v", err)
	}

	if !result.Success {
		log.Fatalf("Certificate renewal failed: %s", result.Message)
	}

	fmt.Printf("Certificate renewed successfully!\n")
	fmt.Printf("Domain: %s\n", result.Domain)
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

	// Type assert for certificate list ([]ssl.CertificateInfo)
	certList, ok := result.Items.([]ssl.CertificateInfo)
	if !ok {
		log.Fatalf("Invalid certificate list format")
	}

	for i, cert := range certList {
		fmt.Printf("[%d] %s\n", i+1, cert.Domain)
		fmt.Printf("    Certificate ID: %s\n", cert.CertificateID)
		fmt.Printf("    Status: %s\n", cert.StatusName)

		// Show certificate type
		var types []string
		if cert.IsWildcard {
			types = append(types, "Wildcard")
		}
		if cert.IsDv {
			types = append(types, "DV")
		}
		if cert.IsVip {
			types = append(types, "VIP")
		}
		if len(types) > 0 {
			fmt.Printf("    Type: %s\n", strings.Join(types, ", "))
		}

		// Show expiry information
		if cert.RemainingDays > 0 {
			fmt.Printf("    Expires: %s (%d days remaining)\n", cert.CertEndTime, cert.RemainingDays)
		} else if cert.RemainingDays == 0 && cert.CertEndTime != "" {
			fmt.Printf("    Expires: %s (expired)\n", cert.CertEndTime)
		}

		if cert.Alias != "" {
			fmt.Printf("    Alias: %s\n", cert.Alias)
		}
		fmt.Println()
	}
}

func (c *CLI) listQiniuCommand(args []string) {
	// Check if Qiniu client is configured
	accessKey := os.Getenv("QINIU_ACCESS_KEY")
	secretKey := os.Getenv("QINIU_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		fmt.Println("Qiniu client is not configured.")
		fmt.Println("Please set the following environment variables:")
		fmt.Println("  QINIU_ACCESS_KEY - Qiniu AccessKey")
		fmt.Println("  QINIU_SECRET_KEY - Qiniu SecretKey")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Create Qiniu client
	qiniuClient, err := qiniu.NewClient(accessKey, secretKey)
	if err != nil {
		log.Fatalf("Failed to create Qiniu client: %v", err)
	}

	certs, err := qiniuClient.ListCertificates(ctx)
	if err != nil {
		log.Fatalf("Failed to list Qiniu certificates: %v", err)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found on Qiniu.")
		return
	}

	// Statistics
	var validCount, expiringCount, expiredCount int
	warningDays := c.cfg.CertExpiryWarningDays
	if warningDays == 0 {
		warningDays = 30
	}

	for _, cert := range certs {
		if cert.NotAfter > 0 {
			expiryTime := time.Unix(cert.NotAfter, 0)
			remainingDays := int(time.Until(expiryTime).Hours() / 24)
			if remainingDays < 0 {
				expiredCount++
			} else if remainingDays <= warningDays {
				expiringCount++
			} else {
				validCount++
			}
		} else {
			validCount++
		}
	}

	fmt.Printf("=== Qiniu Cloud SSL Certificates ===\n\n")
	fmt.Printf("Total: %d | Valid: %d | Expiring soon: %d | Expired: %d\n\n", len(certs), validCount, expiringCount, expiredCount)

	for i, cert := range certs {
		fmt.Printf("[%d] %s\n", i+1, cert.CommonName)
		fmt.Printf("    Cert ID: %s\n", cert.CertID)
		if cert.Name != "" && cert.Name != cert.CommonName {
			fmt.Printf("    Name: %s\n", cert.Name)
		}

		// Certificate type info
		var typeInfo []string
		if cert.CertType != "" {
			typeInfo = append(typeInfo, cert.CertType)
		}
		if cert.ProductType != "" {
			switch cert.ProductType {
			case "single":
				typeInfo = append(typeInfo, "Single")
			case "multi":
				typeInfo = append(typeInfo, "Multi-domain")
			case "wildcard":
				typeInfo = append(typeInfo, "Wildcard")
			}
		}
		if cert.Encrypt != "" {
			typeInfo = append(typeInfo, cert.Encrypt)
		}
		if len(typeInfo) > 0 {
			fmt.Printf("    Type: %s\n", strings.Join(typeInfo, " / "))
		}

		// Show all DNS names (for multi-domain certs)
		if len(cert.DNSNames) > 1 {
			fmt.Printf("    DNS Names:\n")
			for _, name := range cert.DNSNames {
				fmt.Printf("      - %s\n", name)
			}
		}

		// Format timestamps with expiry status
		if cert.NotBefore > 0 && cert.NotAfter > 0 {
			notBefore := time.Unix(cert.NotBefore, 0).Format("2006-01-02")
			notAfter := time.Unix(cert.NotAfter, 0).Format("2006-01-02")
			expiryTime := time.Unix(cert.NotAfter, 0)
			remainingDays := int(time.Until(expiryTime).Hours() / 24)

			var status string
			if remainingDays < 0 {
				status = "EXPIRED"
			} else if remainingDays <= warningDays {
				status = "EXPIRING SOON"
			} else {
				status = "OK"
			}

			fmt.Printf("    Valid: %s ~ %s\n", notBefore, notAfter)
			if remainingDays < 0 {
				fmt.Printf("    Status: %s (expired %d days ago)\n", status, -remainingDays)
			} else if remainingDays <= warningDays {
				fmt.Printf("    Status: %s (%d days remaining)\n", status, remainingDays)
			} else {
				fmt.Printf("    Status: %s (%d days remaining)\n", status, remainingDays)
			}
		}

		// Additional flags
		var flags []string
		if cert.Enable {
			flags = append(flags, "Enabled")
		} else {
			flags = append(flags, "Disabled")
		}
		if cert.AutoRenew {
			flags = append(flags, "AutoRenew")
		}
		if cert.Renewable {
			flags = append(flags, "Renewable")
		}
		fmt.Printf("    Flags: %s\n", strings.Join(flags, ", "))

		if cert.CreateTime > 0 {
			createTime := time.Unix(cert.CreateTime, 0).Format("2006-01-02 15:04")
			fmt.Printf("    Created: %s\n", createTime)
		}
		fmt.Println()
	}
}

func (c *CLI) deleteQiniuCommand(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: ssl-manager delete-qiniu <cert-id>")
		os.Exit(1)
	}

	certID := args[0]

	// Check Qiniu credentials
	accessKey := os.Getenv("QINIU_ACCESS_KEY")
	secretKey := os.Getenv("QINIU_SECRET_KEY")

	if accessKey == "" || secretKey == "" {
		fmt.Println("Qiniu client is not configured.")
		fmt.Println("Please set QINIU_ACCESS_KEY and QINIU_SECRET_KEY")
		os.Exit(1)
	}

	// Create Qiniu client and delete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	qiniuClient, err := qiniu.NewClient(accessKey, secretKey)
	if err != nil {
		log.Fatalf("Failed to create Qiniu client: %v", err)
	}

	if err := qiniuClient.Delete(ctx, certID); err != nil {
		log.Fatalf("Failed to delete certificate: %v", err)
	}

	fmt.Printf("Certificate %s deleted successfully from Qiniu!\n", certID)
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
	fmt.Println("  list        List certificates on Tencent Cloud")
	fmt.Println("  list-qiniu    List certificates on Qiniu Cloud")
	fmt.Println("  delete-qiniu  Delete a certificate from Qiniu Cloud by cert-id")
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
	fmt.Println()
	fmt.Println("Qiniu Cloud (optional):")
	fmt.Println("  QINIU_ACCESS_KEY          Qiniu Cloud AccessKey")
	fmt.Println("  QINIU_SECRET_KEY          Qiniu Cloud SecretKey")
}
