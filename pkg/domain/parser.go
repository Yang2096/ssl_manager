package domain

import (
	"fmt"
	"strings"
)

// ParserResult represents the result of parsing a domain
type ParserResult struct {
	Domain     string `json:"domain"`
	MainDomain string `json:"main_domain"`
	SubDomain  string `json:"sub_domain"`
}

// Public suffixes that should be treated as a single unit
var publicSuffixes = []string{
	"com", "net", "org", "cn", "co.uk", "com.cn", "org.cn", "net.cn",
	"gov.cn", "edu.cn", "ac.cn", "museum", "travel", "blog", "aero",
}

// ParseDomain parses a domain into main domain and subdomain
func ParseDomain(domain string) (*ParserResult, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	// Remove any protocol prefix
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	var mainDomain, subDomain string

	// Handle wildcard domains
	if strings.HasPrefix(domain, "*.") {
		mainDomain = strings.TrimPrefix(domain, "*.")
		subDomain = "*"
	} else if len(parts) == 2 {
		// Simple domain like example.com
		mainDomain = domain
		subDomain = "@"
	} else {
		// Try to find public suffix
		found := false
		for _, suffix := range publicSuffixes {
			suffixParts := strings.Split(suffix, ".")
			if len(parts) > len(suffixParts) {
				domainSuffix := strings.Join(parts[len(parts)-len(suffixParts):], ".")
				if domainSuffix == suffix {
					mainDomain = strings.Join(parts[len(parts)-len(suffixParts)-1:], ".")
					if len(parts) > len(suffixParts)+1 {
						subDomain = strings.Join(parts[:len(parts)-len(suffixParts)-1], ".")
					} else {
						subDomain = "@"
					}
					found = true
					break
				}
			}
		}

		if !found {
			// Default: last two parts as main domain
			mainDomain = strings.Join(parts[len(parts)-2:], ".")
			if len(parts) > 2 {
				subDomain = strings.Join(parts[:len(parts)-2], ".")
			} else {
				subDomain = "@"
			}
		}
	}

	return &ParserResult{
		Domain:     domain,
		MainDomain: mainDomain,
		SubDomain:  subDomain,
	}, nil
}

// IsWildcardDomain checks if a domain is a wildcard domain
func IsWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

// ExtractBaseDomain extracts the base domain from a domain
func ExtractBaseDomain(domain string) (string, error) {
	result, err := ParseDomain(domain)
	if err != nil {
		return "", err
	}
	return result.MainDomain, nil
}

// GetDNSRecordName returns the DNS record name for ACME challenge
func GetDNSRecordName(domain string) string {
	if IsWildcardDomain(domain) {
		return "_acme-challenge." + strings.TrimPrefix(domain, "*.")
	}
	return "_acme-challenge." + domain
}

// NormalizeDomain normalizes a domain for comparison
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	return domain
}

// ContainsDomain checks if a domain is in a list
func ContainsDomain(domains []string, target string) bool {
	target = NormalizeDomain(target)
	for _, d := range domains {
		if NormalizeDomain(d) == target {
			return true
		}
	}
	return false
}

// GetAcmeChallengeDomain returns the domain for ACME DNS challenge
func GetAcmeChallengeDomain(domain string) string {
	// For wildcard domains, we need to use the base domain
	if IsWildcardDomain(domain) {
		return "_acme-challenge." + strings.TrimPrefix(domain, "*.")
	}
	return "_acme-challenge." + domain
}

// SplitCertDomain splits a certificate domain to get the base domain for DNS operations
func SplitCertDomain(acmeChallengeDomain string) (string, string, error) {
	// Input format: _acme-challenge.sub.example.com
	// Output: example.com, sub
	parts := strings.Split(acmeChallengeDomain, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid ACME challenge domain: %s", acmeChallengeDomain)
	}

	// Remove _acme-challenge prefix
	if parts[0] == "_acme-challenge" {
		parts = parts[1:]
	}

	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid domain after removing ACME prefix: %s", acmeChallengeDomain)
	}

	// Get main domain
	mainDomain := strings.Join(parts[len(parts)-2:], ".")

	// Get subdomain
	var subDomain string
	if len(parts) > 2 {
		subDomain = strings.Join(parts[:len(parts)-2], ".")
	} else {
		subDomain = "_acme-challenge"
	}

	return mainDomain, subDomain, nil
}
