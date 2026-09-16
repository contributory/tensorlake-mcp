package tensorlake

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`

func newInitializeRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(initializeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	return req
}

func TestMCPRequiresTensorlakeAPIKey(t *testing.T) {
	req := newInitializeRequest("/mcp")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMCPInitializeWithBearerTensorlakeAPIKey(t *testing.T) {
	req := newInitializeRequest("/mcp")
	req.Header.Set("Authorization", "Bearer test-tensorlake-key")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"serverInfo"`) {
		t.Fatalf("initialize response missing serverInfo: %s", w.Body.String())
	}
}

func TestMCPInitializeWithTensorlakeAPIKeyQueryParam(t *testing.T) {
	req := newInitializeRequest("/mcp?tensorlake_api_key=test-query-key")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPInitializeWithAPIKeyQueryAlias(t *testing.T) {
	req := newInitializeRequest("/mcp?api_key=test-query-alias")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBearerTakesPrecedenceOverQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp?api_key=query-key", nil)
	req.Header.Set("Authorization", "Bearer bearer-key")
	if got := apiKeyFromRequest(req); got != "bearer-key" {
		t.Fatalf("expected bearer key, got %q", got)
	}
}
