package qiniu

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/qiniu/go-sdk/v7/auth"
)

const (
	// BaseURL is the Qiniu API base URL
	BaseURL = "https://api.qiniu.com"
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 30 * time.Second
)

// Client is the Qiniu API client
type Client struct {
	accessKey  string
	secretKey  string
	mac        *auth.Credentials
	httpClient *http.Client
}

// NewClient creates a new Qiniu client
func NewClient(accessKey, secretKey string) (*Client, error) {
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("access key and secret key are required")
	}

	mac := auth.New(accessKey, secretKey)

	return &Client{
		accessKey: accessKey,
		secretKey: secretKey,
		mac:       mac,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}, nil
}

// IsEnabled checks if the client is properly configured
func (c *Client) IsEnabled() bool {
	return c != nil && c.accessKey != "" && c.secretKey != ""
}

// doRequest performs an HTTP request with Qiniu authentication
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	var bodyBytes []byte

	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	reqURL := BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Sign the request using Qiniu V2 signature
	if err := c.signRequest(req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Log request details
	logRequestDetails(req, bodyBytes)

	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("[Qiniu] Request failed: %v", err)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Log response details
	duration := time.Since(startTime)
	logResponseDetails(resp, respBody, duration)

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if jsonErr := json.Unmarshal(respBody, &errResp); jsonErr == nil {
			return nil, fmt.Errorf("API error (code %d): %s", errResp.Code, errResp.Message)
		}
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// signRequest signs the HTTP request with Qiniu authentication
func (c *Client) signRequest(req *http.Request) error {
	// Parse the URL to get the path and query
	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Build the string to sign: Method + " " + Path + "?" + Query + "\n" + Body
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	// Use SignRequestV2 for proper authentication
	accessToken, err := c.mac.SignRequest(req)
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	req.Header.Set("Authorization", "QBox "+accessToken)
	return nil
}

// logRequestDetails logs request information
func logRequestDetails(req *http.Request, body []byte) {
	log.Printf("[Qiniu] %s %s", req.Method, req.URL.Path)
	if len(body) > 0 && len(body) < 200 {
		log.Printf("[Qiniu] Body: %s", string(body))
	}
}

// logResponseDetails logs response information
func logResponseDetails(resp *http.Response, body []byte, duration time.Duration) {
	log.Printf("[Qiniu] %d %s (%v)", resp.StatusCode, resp.Status, duration)
	if len(body) > 0 && len(body) < 200 {
		log.Printf("[Qiniu] Response: %s", string(body))
	}
}
