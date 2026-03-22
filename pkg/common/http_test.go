package common

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPRequest_WithExtraHeaders(t *testing.T) {
	// Create a test server that verifies headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the User-Agent header
		if r.Header.Get("User-Agent") != "TestUserAgent" {
			t.Errorf("Expected User-Agent header to be 'TestUserAgent', got '%s'", r.Header.Get("User-Agent"))
		}
		// Verify the custom header
		if r.Header.Get("X-Custom-Header") != "CustomValue" {
			t.Errorf("Expected X-Custom-Header to be 'CustomValue', got '%s'", r.Header.Get("X-Custom-Header"))
		}
		// Verify authorization header
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Expected Authorization header to be 'Bearer test-token', got '%s'", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	extraHeaders := map[string]string{
		"User-Agent":      "TestUserAgent",
		"X-Custom-Header": "CustomValue",
	}

	resp, err := HTTPPRequest("POST", server.URL, []byte("test data"), "test-token", extraHeaders)
	if err != nil {
		t.Fatalf("HTTPPRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestHTTPPRequest_WithNilExtraHeaders(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Test with nil extraHeaders - should not cause panic
	resp, err := HTTPPRequest("POST", server.URL, []byte("test data"), "", nil)
	if err != nil {
		t.Fatalf("HTTPPRequest with nil extraHeaders failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestHTTPPRequest_WithEmptyExtraHeaders(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Test with empty extraHeaders map
	extraHeaders := make(map[string]string)
	resp, err := HTTPPRequest("POST", server.URL, []byte("test data"), "", extraHeaders)
	if err != nil {
		t.Fatalf("HTTPPRequest with empty extraHeaders failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestHTTPPRequest_InvalidHTTPType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := HTTPPRequest("GET", server.URL, []byte("test data"), "", nil)
	if err == nil {
		t.Fatal("Expected error for invalid HTTP type, got nil")
	}
}

func TestHTTPPRequest_PUT(t *testing.T) {
	// Create a test server that verifies the method is PUT
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected method PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	resp, err := HTTPPRequest("PUT", server.URL, []byte("test data"), "", nil)
	if err != nil {
		t.Fatalf("HTTPPRequest with PUT failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}
}

func TestMAAClientUserAgent_Integration(t *testing.T) {
	// Test that MAAClientUserAgent can be set and used
	testUA := "TestAgent/1.0"

	// Create a test server that verifies User-Agent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != testUA {
			t.Errorf("Expected User-Agent '%s', got '%s'", testUA, r.Header.Get("User-Agent"))
		}
		w.WriteHeader(http.StatusOK)
		// Return a minimal valid MAA response
		_, err := w.Write([]byte(`{"token":"eyJhbGciOiJub25lIn0.e30."}`))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	// Create extraHeaders with User-Agent
	extraHeaders := map[string]string{
		"User-Agent": testUA,
	}

	resp, err := HTTPPRequest("POST", server.URL, []byte("test"), "", extraHeaders)
	if err != nil {
		t.Fatalf("HTTPPRequest failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
	}
}
