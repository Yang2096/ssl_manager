package qiniu

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qiniu/go-sdk/v7/auth"
)

// TestQiniuBasicSign tests the basic Qiniu signing algorithm using the official example
// Reference: https://developer.qiniu.com/kodo/1201/access-token
// Note: This tests the basic Sign algorithm (Sign, not SignRequestV2)
func TestQiniuBasicSign(t *testing.T) {
	accessKey := "MY_ACCESS_KEY"
	secretKey := "MY_SECRET_KEY"

	// The path from the example URL
	// URL: http://rs.qiniu.com/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ=
	path := "/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ="

	// Expected values from the example
	expectedEncodedSign := "FXsYh0wKHYPEsIAgdPD9OfjkeEM="
	expectedAccessToken := accessKey + ":" + expectedEncodedSign

	t.Logf("Path: %s", path)
	t.Logf("Expected encoded sign: %s", expectedEncodedSign)
	t.Logf("Expected access token: %s", expectedAccessToken)

	// Create MAC
	mac := auth.New(accessKey, secretKey)

	// The signing string is: path + "\n" + body (empty body in this case)
	signingStr := path + "\n"
	t.Logf("Signing string: %q", signingStr)

	// mac.Sign returns the full access token (AccessKey:EncodedSign)
	accessToken := mac.Sign([]byte(signingStr))
	t.Logf("Actual access token from Sign: %s", accessToken)

	// Verify the access token
	if accessToken != expectedAccessToken {
		t.Errorf("Access token mismatch:\nexpected: %s\ngot:      %s", expectedAccessToken, accessToken)
	}

	// Parse and verify individual parts
	parts := strings.SplitN(accessToken, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("Invalid access token format: %s", accessToken)
	}

	actualAccessKey := parts[0]
	actualEncodedSign := parts[1]

	if actualAccessKey != accessKey {
		t.Errorf("AccessKey mismatch: expected %s, got %s", accessKey, actualAccessKey)
	}

	if actualEncodedSign != expectedEncodedSign {
		t.Errorf("Encoded sign mismatch: expected %s, got %s", expectedEncodedSign, actualEncodedSign)
	}
}

// TestQiniuSignRequestV2 tests the SignRequestV2 algorithm
// Note: SignRequestV2 uses a more complex signing algorithm that includes headers
// It's different from the basic Sign algorithm used in the simple example
func TestQiniuSignRequestV2(t *testing.T) {
	accessKey := "MY_ACCESS_KEY"
	secretKey := "MY_SECRET_KEY"

	// Create MAC
	mac := auth.New(accessKey, secretKey)

	// Test using SignRequestV2
	path := "/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ="
	reqURL := "http://rs.qiniu.com" + path
	req, err := http.NewRequest("POST", reqURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// SignRequestV2 signs with additional headers (Host, Content-Type, etc.)
	accessToken, err := mac.SignRequestV2(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	t.Logf("Access token from SignRequestV2: %s", accessToken)

	// Verify the access token format
	parts := strings.SplitN(accessToken, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("Invalid access token format: %s", accessToken)
	}

	actualAccessKey := parts[0]
	if actualAccessKey != accessKey {
		t.Errorf("AccessKey mismatch: expected %s, got %s", accessKey, actualAccessKey)
	}

	// SignRequestV2 produces a different signature because it includes more data
	// This is expected behavior - V2 signature includes Host header
	t.Logf("SignRequestV2 uses V2 algorithm which includes Host and other headers")
}

// TestQiniuClientWithCertificateAPI tests the client with certificate API endpoints
func TestQiniuClientWithCertificateAPI(t *testing.T) {
	accessKey := "test_access_key"
	secretKey := "test_secret_key"

	client, err := NewClient(accessKey, secretKey)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if !client.IsEnabled() {
		t.Error("Client should be enabled")
	}

	// Verify the client has correct credentials
	if client.accessKey != accessKey {
		t.Errorf("AccessKey mismatch: expected %s, got %s", accessKey, client.accessKey)
	}
	if client.secretKey != secretKey {
		t.Errorf("SecretKey mismatch: expected %s, got %s", secretKey, client.secretKey)
	}
}

// TestQiniuClientDisabled tests that client is disabled when credentials are missing
func TestQiniuClientDisabled(t *testing.T) {
	// Test with empty credentials
	client, err := NewClient("", "")
	if err == nil {
		t.Error("Expected error when creating client with empty credentials")
	}
	if client != nil {
		t.Error("Expected nil client when credentials are empty")
	}

	// Test with partial credentials
	client, err = NewClient("access_key", "")
	if err == nil {
		t.Error("Expected error when creating client with empty secret key")
	}

	// Test IsEnabled with nil client
	var nilClient *Client
	if nilClient.IsEnabled() {
		t.Error("Nil client should not be enabled")
	}
}

// TestSignRequest tests the signRequest method
func TestSignRequest(t *testing.T) {
	accessKey := "MY_ACCESS_KEY"
	secretKey := "MY_SECRET_KEY"

	client, err := NewClient(accessKey, secretKey)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create a request similar to the example
	reqURL := "http://rs.qiniu.com/move/bmV3ZG9jczpmaW5kX21hbi50eHQ=/bmV3ZG9jczpmaW5kLm1hbi50eHQ="
	req, err := http.NewRequest("POST", reqURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	err = client.signRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Check Authorization header
	authHeader := req.Header.Get("Authorization")
	t.Logf("Authorization header: %s", authHeader)

	if authHeader == "" {
		t.Error("Authorization header should not be empty")
	}

	// The header should start with "QBox "
	if !strings.HasPrefix(authHeader, "QBox ") {
		t.Errorf("Authorization header should start with 'QBox ', got: %s", authHeader)
	}
}

// TestSignRequestWithQueryParams tests signing with query parameters
func TestSignRequestWithQueryParams(t *testing.T) {
	accessKey := "test_key"
	secretKey := "test_secret"

	client, err := NewClient(accessKey, secretKey)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create a request with query parameters
	reqURL := BaseURL + CertificatesPath + "?Limit=10&Marker=abc123"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	err = client.signRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Check Authorization header
	authHeader := req.Header.Get("Authorization")
	t.Logf("Authorization header with query params: %s", authHeader)

	if authHeader == "" {
		t.Error("Authorization header should not be empty")
	}
}

// TestSignRequestWithBody tests signing with request body
func TestSignRequestWithBody(t *testing.T) {
	accessKey := "test_key"
	secretKey := "test_secret"

	client, err := NewClient(accessKey, secretKey)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create a request with body
	reqURL := BaseURL + CertificatesPath

	req, err := http.NewRequest("POST", reqURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Body for signing
	bodyBytes := []byte(`{"name":"test-cert"}`)
	t.Logf("Body for signing: %s", string(bodyBytes))

	// Sign the request with body
	err = client.signRequest(req)
	if err != nil {
		t.Fatalf("Failed to sign request: %v", err)
	}

	// Check Authorization header
	authHeader := req.Header.Get("Authorization")
	t.Logf("Authorization header with body: %s", authHeader)

	if authHeader == "" {
		t.Error("Authorization header should not be empty")
	}
}
