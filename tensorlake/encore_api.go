package tensorlake

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type tenantAPIKeyContextKey struct{}

type tenantMCPServer struct {
	impl *mcp.Server
}

var (
	handlerOnce sync.Once
	mcpHandler  http.Handler

	tenantMu      sync.Mutex
	tenantServers = make(map[[32]byte]*tenantMCPServer)
)

func apiKeyFromRequest(req *http.Request) string {
	if value, ok := req.Context().Value(tenantAPIKeyContextKey{}).(string); ok && value != "" {
		return value
	}

	if auth := strings.TrimSpace(req.Header.Get("Authorization")); auth != "" {
		parts := strings.Fields(auth)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			if key := strings.TrimSpace(parts[1]); key != "" {
				return key
			}
		}
	}

	for _, name := range []string{"tensorlake_api_key", "api_key"} {
		if key := strings.TrimSpace(req.URL.Query().Get(name)); key != "" {
			return key
		}
	}

	return ""
}

func serverForAPIKey(apiKey string) *mcp.Server {
	hash := sha256.Sum256([]byte(apiKey))

	tenantMu.Lock()
	defer tenantMu.Unlock()

	if existing := tenantServers[hash]; existing != nil {
		return existing.impl
	}

	impl, _ := newMCPServer(apiKey)
	tenantServers[hash] = &tenantMCPServer{impl: impl}
	return impl
}

func handler() http.Handler {
	handlerOnce.Do(func() {
		mcpHandler = mcp.NewStreamableHTTPHandler(
			func(req *http.Request) *mcp.Server {
				return serverForAPIKey(apiKeyFromRequest(req))
			},
			&mcp.StreamableHTTPOptions{
				Stateless:    true,
				JSONResponse: true,
			},
		)
	})
	return mcpHandler
}

// serveMCP extracts the caller's Tensorlake API key from either:
//   - Authorization: Bearer <tensorlake-api-key> (preferred)
//   - ?tensorlake_api_key=<tensorlake-api-key>
//   - ?api_key=<tensorlake-api-key>
//
// The raw key is removed from the cloned request before handing it to the MCP
// transport and is used only to select the caller-specific Tensorlake client.
func serveMCP(w http.ResponseWriter, req *http.Request) {
	apiKey := apiKeyFromRequest(req)
	if apiKey == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tensorlake-mcp"`)
		http.Error(w, "missing Tensorlake API key", http.StatusUnauthorized)
		return
	}

	ctx := context.WithValue(req.Context(), tenantAPIKeyContextKey{}, apiKey)
	cleanReq := req.Clone(ctx)
	cleanReq.Header = req.Header.Clone()
	cleanReq.Header.Del("Authorization")

	cleanURL := *req.URL
	query := cleanURL.Query()
	query.Del("tensorlake_api_key")
	query.Del("api_key")
	cleanURL.RawQuery = query.Encode()
	cleanReq.URL = &cleanURL

	handler().ServeHTTP(w, cleanReq)
}

// MCP exposes the Tensorlake MCP server over MCP Streamable HTTP.
//
//encore:api public raw path=/mcp
func MCP(w http.ResponseWriter, req *http.Request) {
	serveMCP(w, req)
}

// Health reports whether the service process is up. It does not call Tensorlake.
//
//encore:api public method=GET path=/status
func Health(ctx context.Context) (*HealthResponse, error) {
	return &HealthResponse{Status: "ok", Transport: "streamable-http", Stateless: true}, nil
}

type HealthResponse struct {
	Status    string `json:"status"`
	Transport string `json:"transport"`
	Stateless bool   `json:"stateless"`
}
