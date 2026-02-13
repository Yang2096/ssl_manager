package domain

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ParserResult represents the result of parsing a domain
type ParserResult struct {
	Domain     string `json:"domain"`
	MainDomain string `json:"main_domain"`
	SubDomain  string `json:"sub_domain"`
}

// ParseDomain parses a domain into main domain and subdomain
// Uses golang.org/x/net/publicsuffix for accurate public suffix detection
func ParseDomain(domain string) (*ParserResult, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	// Remove any protocol prefix
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Handle wildcard domains
	// publicsuffix doesn't accept wildcard prefixes, so handle separately
	if strings.HasPrefix(domain, "*.") {
		wildcardDomain := strings.TrimPrefix(domain, "*.")
		mainDomain, err := publicsuffix.EffectiveTLDPlusOne(wildcardDomain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse wildcard domain %s: %w", wildcardDomain, err)
		}

		var subDomain string
		if wildcardDomain == mainDomain {
			subDomain = "*"
		} else {
			// Extract subdomain part (everything before mainDomain)
			// Note: The "*. prefix was already stripped, don't add it back
			subDomain = strings.TrimSuffix(wildcardDomain, "."+mainDomain)
		}

		return &ParserResult{
			Domain:     domain,
			MainDomain: mainDomain,
			SubDomain:  subDomain,
		}, nil
	}

	// Get effective TLD+1 (main domain) using publicsuffix
	// For "www.example.com" -> "example.com"
	// For "api.b2b.example.co.uk" -> "example.co.uk"
	mainDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse domain %s: %w", domain, err)
	}

	// Extract subdomain by removing mainDomain from domain
	var subDomain string
	if domain == mainDomain {
		subDomain = "@"
	} else {
		subDomain = strings.TrimSuffix(domain, "."+mainDomain)
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

// ExtractBaseDomain extracts base domain from a domain
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

	// Get main domain using publicsuffix
	fullDomain := strings.Join(parts, ".")
	mainDomain, err := publicsuffix.EffectiveTLDPlusOne(fullDomain)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse domain %s: %w", fullDomain, err)
	}

	// Get subdomain
	var subDomain string
	if fullDomain == mainDomain {
		subDomain = "_acme-challenge"
	} else {
		subDomain = strings.TrimSuffix(fullDomain, "."+mainDomain)
		subDomain = "_acme-challenge." + subDomain
	}

	return mainDomain, subDomain, nil
}
