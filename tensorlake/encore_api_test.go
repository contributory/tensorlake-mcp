package tensorlake

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPRequiresBearerAuth(t *testing.T) {
	secrets.TensorlakeAPIKey = "dummy"
	secrets.MCPBearerToken = "test-token"

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMCPInitialize(t *testing.T) {
	secrets.TensorlakeAPIKey = "dummy"
	secrets.MCPBearerToken = "test-token"

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"serverInfo"`) {
		t.Fatalf("initialize response missing serverInfo: %s", w.Body.String())
	}
}
