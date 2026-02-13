package cert

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/yang/ssl-manager/pkg/ssl"
)

// UrgencyLevel represents the urgency level of a certificate
type UrgencyLevel string

const (
	UrgencyOk       UrgencyLevel = "ok"
	UrgencyWarning  UrgencyLevel = "warning"
	UrgencyCritical UrgencyLevel = "critical"
	UrgencyExpired  UrgencyLevel = "expired"
)

// ExpiryChecker checks certificate expiration
type ExpiryChecker struct {
	daysThreshold int
}

// CertificateStatus represents the status of a certificate
type CertificateStatus struct {
	CertificateID string       `json:"certificate_id"`
	Domain        string       `json:"domain"`
	Alias         string       `json:"alias,omitempty"`
	RemainingDays int          `json:"remaining_days"`
	EndTime       string       `json:"end_time"`
	Status        string       `json:"status"`
	Urgency       UrgencyLevel `json:"urgency"` // ok, warning, critical, expired
}

// CertificateSummary represents a summary of all certificates
type CertificateSummary struct {
	Total            int                `json:"total"`
	Valid            int                `json:"valid"`
	ExpiringSoon      int                `json:"expiring_soon"`      // 30 days
	ExpiringVerySoon  int                `json:"expiring_very_soon"`  // 7 days
	Expired          int                `json:"expired"`
	Certificates     []CertificateStatus `json:"certificates"`
}

// RenewalCandidate represents a certificate that needs renewal
type RenewalCandidate struct {
	CertificateID string `json:"certificate_id"`
	Domain        string `json:"domain"`
	RemainingDays int    `json:"remaining_days"`
	EndTime       string `json:"end_time"`
	Status        string `json:"status"`
	Priority      int    `json:"priority"`
}

// RenewalPlan represents a plan for renewing certificates
type RenewalPlan struct {
	Total      int                 `json:"total"`
	BatchSize  int                 `json:"batch_size"`
	BatchCount int                 `json:"batch_count"`
	Batches    [][]RenewalCandidate `json:"batches"`
}

// SSLCertificateFetcher is an interface for fetching SSL certificates
type SSLCertificateFetcher interface {
	GetCertificateList(ctx context.Context, limit int, offset int, searchKey string) ([]ssl.CertificateInfo, error)
	GetCertificateByDomain(ctx context.Context, domain string) (*ssl.CertificateInfo, error)
}

// NewExpiryChecker creates a new expiry checker
func NewExpiryChecker(daysThreshold int) *ExpiryChecker {
	if daysThreshold <= 0 {
		daysThreshold = 30
	}
	return &ExpiryChecker{
		daysThreshold: daysThreshold,
	}
}

// parseEndTime parses an end time string
func (e *ExpiryChecker) parseEndTime(endTime string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999999Z",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, endTime); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse end time: %s", endTime)
}

// calculateRemainingDays calculates the remaining days until expiration
func (e *ExpiryChecker) calculateRemainingDays(endTime string) (int, error) {
	t, err := e.parseEndTime(endTime)
	if err != nil {
		return 0, err
	}

	duration := time.Until(t)
	return int(duration.Hours() / 24), nil
}

// CheckCertificatesExpiring checks for certificates expiring within the threshold
func (e *ExpiryChecker) CheckCertificatesExpiring(ctx context.Context, fetcher SSLCertificateFetcher) ([]CertificateStatus, error) {
	log.Printf("Checking certificates expiring within %d days", e.daysThreshold)

	certs, err := fetcher.GetCertificateList(ctx, 100, 0, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate list: %w", err)
	}

	var expiring []CertificateStatus

	for i := range certs {
		cert := &certs[i]
		endTime := cert.CertEndTime
		if endTime == "" {
			continue
		}

		remainingDays, err := e.calculateRemainingDays(endTime)
		if err != nil {
			log.Printf("Failed to calculate remaining days for %s: %v", cert.Domain, err)
			continue
		}

		if remainingDays <= e.daysThreshold {
			status := CertificateStatus{
				CertificateID: cert.CertificateID,
				Domain:        cert.Domain,
				Alias:         cert.Alias,
				RemainingDays: remainingDays,
				EndTime:       endTime,
				Status:        cert.Status,
				Urgency:       e.getUrgency(remainingDays),
			}
			expiring = append(expiring, status)
			log.Printf("Certificate %s expires in %d days", status.Domain, remainingDays)
		}
	}

	log.Printf("Found %d expiring certificates", len(expiring))
	return expiring, nil
}

// CheckDomainCertificate checks a specific domain's certificate
func (e *ExpiryChecker) CheckDomainCertificate(ctx context.Context, fetcher SSLCertificateFetcher, domain string) (*CertificateStatus, error) {
	cert, err := fetcher.GetCertificateByDomain(ctx, domain)
	if err != nil || cert == nil {
		return nil, nil
	}

	endTime := cert.CertEndTime
	if endTime == "" {
		return nil, nil
	}

	remainingDays, err := e.calculateRemainingDays(endTime)
	if err != nil {
		return nil, err
	}

	return &CertificateStatus{
		CertificateID: cert.CertificateID,
		Domain:        cert.Domain,
		RemainingDays: remainingDays,
		EndTime:       endTime,
		Status:        cert.Status,
		Urgency:       e.getUrgency(remainingDays),
	}, nil
}

// GetRenewalCandidates gets certificates that need renewal
func (e *ExpiryChecker) GetRenewalCandidates(ctx context.Context, fetcher SSLCertificateFetcher) ([]RenewalCandidate, error) {
	expiring, err := e.CheckCertificatesExpiring(ctx, fetcher)
	if err != nil {
		return nil, err
	}

	var candidates []RenewalCandidate
	for _, cert := range expiring {
		// Skip revoked, expired, or revoking certificates
		status := strings.ToLower(cert.Status)
		if status == "revoked" || status == "expired" || status == "revoking" {
			continue
		}

		candidate := RenewalCandidate{
			CertificateID: cert.CertificateID,
			Domain:        cert.Domain,
			RemainingDays: cert.RemainingDays,
			EndTime:       cert.EndTime,
			Status:        cert.Status,
		}
		candidates = append(candidates, candidate)
	}

	return candidates, nil
}

// CheckAllCertificates returns a summary of all certificates
func (e *ExpiryChecker) CheckAllCertificates(ctx context.Context, fetcher SSLCertificateFetcher) (*CertificateSummary, error) {
	certs, err := fetcher.GetCertificateList(ctx, 100, 0, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate list: %w", err)
	}

	summary := &CertificateSummary{
		Certificates: make([]CertificateStatus, 0),
	}

	for i := range certs {
		cert := &certs[i]
		endTime := cert.CertEndTime
		if endTime == "" {
			continue
		}

		remainingDays, err := e.calculateRemainingDays(endTime)
		if err != nil {
			log.Printf("Failed to calculate remaining days: %v", err)
			continue
		}

		status := CertificateStatus{
			CertificateID: cert.CertificateID,
			Domain:        cert.Domain,
			RemainingDays: remainingDays,
			EndTime:       endTime,
			Status:        cert.Status,
			Urgency:       e.getUrgency(remainingDays),
		}
		summary.Certificates = append(summary.Certificates, status)

		if remainingDays <= 0 {
			summary.Expired++
		} else if remainingDays <= 7 {
			summary.ExpiringVerySoon++
			summary.ExpiringSoon++
		} else if remainingDays <= 30 {
			summary.ExpiringSoon++
		} else {
			summary.Valid++
		}
	}

	summary.Total = len(summary.Certificates)
	return summary, nil
}

// GenerateRenewalPlan generates a renewal plan
func (e *ExpiryChecker) GenerateRenewalPlan(ctx context.Context, fetcher SSLCertificateFetcher, batchSize int) (*RenewalPlan, error) {
	candidates, err := e.GetRenewalCandidates(ctx, fetcher)
	if err != nil {
		return nil, err
	}

	// Sort by remaining days
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].RemainingDays < candidates[j].RemainingDays
	})

	// Create batches
	var batches [][]RenewalCandidate
	for i := 0; i < len(candidates); i += batchSize {
		end := i + batchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batches = append(batches, candidates[i:end])
	}

	return &RenewalPlan{
		Total:      len(candidates),
		BatchSize:  batchSize,
		BatchCount:  len(batches),
		Batches:    batches,
	}, nil
}

// GetPriorityList returns certificates sorted by renewal priority
func (e *ExpiryChecker) GetPriorityList(ctx context.Context, fetcher SSLCertificateFetcher) ([]RenewalCandidate, error) {
	candidates, err := e.GetRenewalCandidates(ctx, fetcher)
	if err != nil {
		return nil, err
	}

	// Calculate priority score
	for i := range candidates {
		candidates[i].Priority = e.calculatePriority(candidates[i].RemainingDays)
	}

	// Sort by priority
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Priority > candidates[j].Priority
	})

	return candidates, nil
}

// calculatePriority calculates a priority score for renewal
func (e *ExpiryChecker) calculatePriority(remainingDays int) int {
	if remainingDays <= 0 {
		return 100
	} else if remainingDays <= 7 {
		return 90 + (7 - remainingDays)
	} else if remainingDays <= 30 {
		return 50 + (30-remainingDays)/2
	}
	return 10
}

// getUrgency returns the urgency level based on remaining days
func (e *ExpiryChecker) getUrgency(remainingDays int) UrgencyLevel {
	if remainingDays <= 0 {
		return UrgencyExpired
	} else if remainingDays <= 7 {
		return UrgencyCritical
	} else if remainingDays <= 30 {
		return UrgencyWarning
	}
	return UrgencyOk
}
