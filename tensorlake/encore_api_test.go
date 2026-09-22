package tensorlake

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`

func newMCPRequest(target, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	return req
}

func newInitializeRequest(target string) *http.Request {
	return newMCPRequest(target, initializeBody)
}

func TestMCPInitializeWithoutCredentialAllowsOAuthDiscovery(t *testing.T) {
	req := newInitializeRequest("https://mcp.example.test/mcp")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"serverInfo"`) {
		t.Fatalf("initialize response missing serverInfo: %s", w.Body.String())
	}
}

func TestUnauthenticatedToolListPublishesOAuthSecurityScheme(t *testing.T) {
	req := newMCPRequest("https://mcp.example.test/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"securitySchemes"`) || !strings.Contains(body, `"oauth2"`) {
		t.Fatalf("tool list missing OAuth security scheme: %s", body)
	}
}

func TestUnauthenticatedToolCallReturnsMCPAuthChallenge(t *testing.T) {
	req := newMCPRequest("https://mcp.example.test/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{"command":"true"}}}`)
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected MCP result over HTTP 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"mcp/www_authenticate"`) {
		t.Fatalf("tool auth error missing mcp/www_authenticate: %s", body)
	}
	if !strings.Contains(body, `resource_metadata=`) || !strings.Contains(body, `error=\\"invalid_token\\"`) {
		t.Fatalf("tool auth challenge missing required OAuth fields: %s", body)
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

func TestOAuthMetadataAdvertisesChatGPTRequirements(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://mcp.example.test/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	writeAuthorizationServerMetadata(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, required := range []string{
		`"authorization_response_iss_parameter_supported":true`,
		`"client_id_metadata_document_supported":true`,
		`"S256"`,
		`"none"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("OAuth metadata missing %s: %s", required, body)
		}
	}
}
