package domain

import (
	"testing"
)

// TestParseDomain_NormalDomains tests normal domain parsing
func TestParseDomain_NormalDomains(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedMain   string
		expectedSub    string
		expectError    bool
	}{
		{
			name:          "Simple domain",
			input:         "example.com",
			expectedMain:   "example.com",
			expectedSub:    "@",
		},
		{
			name:          "Subdomain with www",
			input:         "www.example.com",
			expectedMain:   "example.com",
			expectedSub:    "www",
		},
		{
			name:          "Multi-level subdomain",
			input:         "api.b2b.example.com",
			expectedMain:   "example.com",
			expectedSub:    "api.b2b",
		},
		{
			name:          "Double-barrel TLD",
			input:         "example.co.uk",
			expectedMain:   "example.co.uk",
			expectedSub:    "@",
		},
		{
			name:          "Subdomain with co.uk",
			input:         "www.example.co.uk",
			expectedMain:   "example.co.uk",
			expectedSub:    "www",
		},
		{
			name:          "Chinese domain with com.cn",
			input:         "test.example.com.cn",
			expectedMain:   "example.com.cn",
			expectedSub:    "test",
		},
		{
			name:          "Complex multi-level",
			input:         "api.v2.prod.example.com",
			expectedMain:   "example.com",
			expectedSub:    "api.v2.prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDomain(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseDomain(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseDomain(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result.MainDomain != tt.expectedMain {
				t.Errorf("ParseDomain(%q) MainDomain = %q, want %q",
					tt.input, result.MainDomain, tt.expectedMain)
			}
			if result.SubDomain != tt.expectedSub {
				t.Errorf("ParseDomain(%q) SubDomain = %q, want %q",
					tt.input, result.SubDomain, tt.expectedSub)
			}
		})
	}
}

// TestParseDomain_WildcardDomains tests wildcard domain parsing
func TestParseDomain_WildcardDomains(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedMain   string
		expectedSub    string
		expectError    bool
	}{
		{
			name:          "Wildcard simple domain",
			input:         "*.example.com",
			expectedMain:   "example.com",
			expectedSub:    "*",
		},
		{
			name:          "Wildcard with co.uk",
			input:         "*.example.co.uk",
			expectedMain:   "example.co.uk",
			expectedSub:    "*",
		},
		{
			name:          "Wildcard with subdomain",
			input:         "*.api.example.com",
			expectedMain:   "example.com",
			expectedSub:    "api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDomain(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseDomain(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseDomain(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result.MainDomain != tt.expectedMain {
				t.Errorf("ParseDomain(%q) MainDomain = %q, want %q",
					tt.input, result.MainDomain, tt.expectedMain)
			}
			if result.SubDomain != tt.expectedSub {
				t.Errorf("ParseDomain(%q) SubDomain = %q, want %q",
					tt.input, result.SubDomain, tt.expectedSub)
			}
		})
	}
}

// TestParseDomain_UserDomains tests the user's specific domains
func TestParseDomain_UserDomains(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedMain   string
		expectedSub    string
		expectError    bool
	}{
		{
			name:          "User domain - cdn.laoyangandcompany.online",
			input:         "cdn.laoyangandcompany.online",
			expectedMain:   "laoyangandcompany.online",
			expectedSub:    "cdn",
		},
		{
			name:          "User domain - _acme-challenge.cdn.laoyangandcompany.online",
			input:         "_acme-challenge.cdn.laoyangandcompany.online",
			expectedMain:   "laoyangandcompany.online",
			expectedSub:    "_acme-challenge.cdn",
		},
		{
			name:          "User domain - laoyangandcompany.online root",
			input:         "laoyangandcompany.online",
			expectedMain:   "laoyangandcompany.online",
			expectedSub:    "@",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDomain(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseDomain(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseDomain(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result.MainDomain != tt.expectedMain {
				t.Errorf("ParseDomain(%q) MainDomain = %q, want %q",
					tt.input, result.MainDomain, tt.expectedMain)
			}
			if result.SubDomain != tt.expectedSub {
				t.Errorf("ParseDomain(%q) SubDomain = %q, want %q",
					tt.input, result.SubDomain, tt.expectedSub)
			}
		})
	}
}

// TestParseDomain_EdgeCases tests edge cases
func TestParseDomain_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedMain   string
		expectedSub    string
		expectError    bool
	}{
		{
			name:       "Empty domain",
			input:      "",
			expectError: true,
		},
		{
			name:       "Single label",
			input:      "localhost",
			expectError: true,
		},
		{
			name:          "Domain with http prefix",
			input:         "http://example.com",
			expectedMain:   "example.com",
			expectedSub:    "@",
		},
		{
			name:          "Domain with https prefix",
			input:         "https://example.com",
			expectedMain:   "example.com",
			expectedSub:    "@",
		},
		{
			name:          "Domain with www prefix",
			input:         "www.example.com",
			expectedMain:   "example.com",
			expectedSub:    "www",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDomain(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseDomain(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseDomain(%q) unexpected error: %v", tt.input, err)
				return
			}
			if result.MainDomain != tt.expectedMain {
				t.Errorf("ParseDomain(%q) MainDomain = %q, want %q",
					tt.input, result.MainDomain, tt.expectedMain)
			}
			if result.SubDomain != tt.expectedSub {
				t.Errorf("ParseDomain(%q) SubDomain = %q, want %q",
					tt.input, result.SubDomain, tt.expectedSub)
			}
		})
	}
}

// TestNormalizeDomain tests domain normalization
func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"  Example.com  ", "example.com"},
		{"HTTP://example.com/", "example.com"},
		{"https://EXAMPLE.COM/", "example.com"},
		{"example.com/", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsWildcardDomain tests wildcard domain detection
func TestIsWildcardDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"*.example.com", true},
		{"*.test.example.com", true},
		{"example.com", false},
		{"www.example.com", false},
		{"*example.com", false}, // missing dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsWildcardDomain(tt.input)
			if result != tt.expected {
				t.Errorf("IsWildcardDomain(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
