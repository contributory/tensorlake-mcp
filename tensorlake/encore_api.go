package tensorlake

import (
	"context"
	"crypto/sha256"
	"errors"
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

func resolveTensorlakeAPIKey(req *http.Request) (string, error) {
	credential := apiKeyFromRequest(req)
	if credential == "" {
		return "", nil
	}
	if strings.HasPrefix(credential, oauthAccessTokenPrefix) {
		return apiKeyForOAuthAccessToken(req, credential)
	}
	// Backward compatibility: a non-OAuth Bearer value or the legacy query
	// parameters are treated as a raw Tensorlake API key.
	return credential, nil
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

func writeOAuthChallenge(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("WWW-Authenticate", oauthChallenge(req))
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "OAuth authorization required", http.StatusUnauthorized)
}

// serveMCP resolves a ChatGPT/MCP OAuth access token to its stored Tensorlake
// API key. Raw Tensorlake Bearer/query credentials remain supported for
// backwards compatibility with existing clients.
func serveMCP(w http.ResponseWriter, req *http.Request) {
	apiKey, err := resolveTensorlakeAPIKey(req)
	if errors.Is(err, errInvalidAccessToken) {
		apiKey = ""
	} else if err != nil {
		http.Error(w, "authorization service unavailable", http.StatusServiceUnavailable)
		return
	}

	ctx := context.WithValue(req.Context(), tenantAPIKeyContextKey{}, apiKey)
	ctx = context.WithValue(ctx, oauthChallengeContextKey{}, oauthChallenge(req))
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
