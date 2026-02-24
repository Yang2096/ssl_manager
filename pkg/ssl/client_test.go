package ssl

import (
	"testing"
)

func TestSortCertificatesByEndTime(t *testing.T) {
	tests := []struct {
		name     string
		input    []CertificateInfo
		expected []string // expected order of certificate IDs
	}{
		{
			name:     "empty list",
			input:    []CertificateInfo{},
			expected: []string{},
		},
		{
			name: "single certificate",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "2024-06-01 00:00:00"},
			},
			expected: []string{"cert1"},
		},
		{
			name: "sorted descending by end time",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "2024-03-01 00:00:00"},
				{CertificateID: "cert2", CertEndTime: "2024-06-01 00:00:00"},
				{CertificateID: "cert3", CertEndTime: "2024-01-01 00:00:00"},
			},
			expected: []string{"cert2", "cert1", "cert3"},
		},
		{
			name: "already sorted",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "2024-06-01 00:00:00"},
				{CertificateID: "cert2", CertEndTime: "2024-03-01 00:00:00"},
			},
			expected: []string{"cert1", "cert2"},
		},
		{
			name: "with invalid time format - invalid goes to end",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "2024-06-01 00:00:00"},
				{CertificateID: "cert2", CertEndTime: "invalid-time"},
				{CertificateID: "cert3", CertEndTime: "2024-03-01 00:00:00"},
			},
			expected: []string{"cert1", "cert3", "cert2"},
		},
		{
			name: "both invalid times - keep original order",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "invalid-1"},
				{CertificateID: "cert2", CertEndTime: "invalid-2"},
			},
			expected: []string{"cert1", "cert2"},
		},
		{
			name: "first invalid second valid - valid comes first",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "invalid-time"},
				{CertificateID: "cert2", CertEndTime: "2024-06-01 00:00:00"},
			},
			expected: []string{"cert2", "cert1"},
		},
		{
			name: "same end time",
			input: []CertificateInfo{
				{CertificateID: "cert1", CertEndTime: "2024-06-01 12:00:00"},
				{CertificateID: "cert2", CertEndTime: "2024-06-01 12:00:00"},
			},
			expected: []string{"cert1", "cert2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to avoid modifying the test data
			certs := make([]CertificateInfo, len(tt.input))
			copy(certs, tt.input)

			sortCertificatesByEndTime(certs)

			if len(certs) != len(tt.expected) {
				t.Errorf("expected %d certificates, got %d", len(tt.expected), len(certs))
				return
			}

			for i, cert := range certs {
				if cert.CertificateID != tt.expected[i] {
					t.Errorf("position %d: expected cert ID %s, got %s", i, tt.expected[i], cert.CertificateID)
				}
			}
		})
	}
}

func TestGetBool(t *testing.T) {
	tests := []struct {
		name     string
		input    *bool
		expected bool
	}{
		{
			name:     "nil pointer",
			input:    nil,
			expected: false,
		},
		{
			name:     "true value",
			input:    boolPtr(true),
			expected: true,
		},
		{
			name:     "false value",
			input:    boolPtr(false),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBool(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
