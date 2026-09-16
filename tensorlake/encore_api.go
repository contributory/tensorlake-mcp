package tensorlake

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var secrets struct {
	TensorlakeAPIKey string
	MCPBearerToken   string
}

var (
	handlerOnce sync.Once
	mcpHandler  http.Handler
)

func handler() http.Handler {
	handlerOnce.Do(func() {
		tlAPIKey = secrets.TensorlakeAPIKey
		impl, _ := newMCPServer()
		mcpHandler = mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return impl },
			&mcp.StreamableHTTPOptions{
				Stateless:    true,
				JSONResponse: true,
			},
		)
	})
	return mcpHandler
}

func authorized(req *http.Request) bool {
	got := req.Header.Get("Authorization")
	want := "Bearer " + secrets.MCPBearerToken
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// MCP exposes the Tensorlake MCP server over the MCP Streamable HTTP transport.
// The MCP transport is intentionally stateless; keep this deployment single-instance because the upstream Tensorlake workspace cache is process-local.
//
// Internal implementation used by the Encore raw endpoint and unit tests.
func serveMCP(w http.ResponseWriter, req *http.Request) {
	if !authorized(req) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tensorlake-mcp"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	handler().ServeHTTP(w, req)
}

//encore:api public raw path=/mcp
func MCP(w http.ResponseWriter, req *http.Request) {
	serveMCP(w, req)
}

// Health reports whether the service process is up. It does not call Tensorlake.
//
//encore:api public method=GET path=/healthz
func Health(ctx context.Context) (*HealthResponse, error) {
	return &HealthResponse{Status: "ok", Transport: "streamable-http", Stateless: true}, nil
}

type HealthResponse struct {
	Status    string `json:"status"`
	Transport string `json:"transport"`
	Stateless bool   `json:"stateless"`
}

// Unauthorized is kept small and JSON-safe for clients that probe the endpoint.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
