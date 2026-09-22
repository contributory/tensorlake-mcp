package tensorlake

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const initializeBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}"

func newMCPRequest(target, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	return req
}

func newInitializeRequest(target string) *http.Request {
	return newMCPRequest(target, initializeBody)
}

func TestMCPWithoutBearerRequiresOAuth(t *testing.T) {
	req := newInitializeRequest("https://mcp.example.test/mcp")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	challenge := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata=") || !strings.Contains(challenge, "scope=\"mcp\"") {
		t.Fatalf("missing OAuth challenge: %q", challenge)
	}
}

func TestUnauthenticatedToolListRequiresOAuthBeforeDiscovery(t *testing.T) {
	req := newMCPRequest("https://mcp.example.test/mcp", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 before tool discovery, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("missing OAuth challenge: %q", got)
	}
}

func TestUnauthenticatedToolCallRequiresOAuthAtHTTPBoundary(t *testing.T) {
	req := newMCPRequest("https://mcp.example.test/mcp", "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"bash\",\"arguments\":{\"command\":\"true\"}}}")
	w := httptest.NewRecorder()

	serveMCP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
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
	if !strings.Contains(w.Body.String(), "\"serverInfo\"") {
		t.Fatalf("initialize response missing serverInfo: %s", w.Body.String())
	}
}

func TestQueryAPIKeyDoesNotBypassRequiredOAuth(t *testing.T) {
	for _, target := range []string{
		"/mcp?tensorlake_api_key=test-query-key",
		"/mcp?api_key=test-query-alias",
	} {
		req := newInitializeRequest(target)
		w := httptest.NewRecorder()

		serveMCP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d: %s", target, w.Code, w.Body.String())
		}
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
		"\"authorization_response_iss_parameter_supported\":true",
		"\"client_id_metadata_document_supported\":true",
		"\"S256\"",
		"\"none\"",
		"\"private_key_jwt\"",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("OAuth metadata missing %s: %s", required, body)
		}
	}
}

func TestAuthorizePageAllowsRegisteredRedirectOriginInCSP(t *testing.T) {
	w := httptest.NewRecorder()
	renderAuthorizePage(w, &oauthClient{ID: "chatgpt", Name: "ChatGPT"}, authorizationRequest{
		ClientID:    "https://chatgpt.com/oauth/client.json",
		RedirectURI: "https://chatgpt.com/connector_platform_oauth_redirect",
		Scope:       "mcp",
	})
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://chatgpt.com") {
		t.Fatalf("authorize CSP does not allow registered callback origin: %q", csp)
	}
}
