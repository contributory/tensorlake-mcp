package tensorlake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	encore "encore.dev"
)

const (
	oauthScopeMCP           = "mcp"
	oauthScopeOffline       = "offline_access"
	oauthAccessTokenPrefix  = "tlmcp_at_"
	oauthRefreshTokenPrefix = "tlmcp_rt_"
	oauthCodePrefix         = "tlmcp_code_"
	oauthClientPrefix       = "tlmcp_client_"
)

var errInvalidAccessToken = errors.New("invalid or expired OAuth access token")

type oauthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
}

type clientMetadataDocument struct {
	ClientID                          string   `json:"client_id"`
	ClientName                        string   `json:"client_name,omitempty"`
	RedirectURIs                      []string `json:"redirect_uris"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

func randomOpaque(prefix string, bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func encoreAPIOrigin() (origin string) {
	defer func() {
		if recover() != nil {
			origin = ""
		}
	}()
	meta := encore.Meta()
	if meta == nil || meta.APIBaseURL.Scheme == "" || meta.APIBaseURL.Host == "" {
		return ""
	}
	return strings.TrimRight(meta.APIBaseURL.String(), "/")
}

func requestOrigin(req *http.Request) string {
	// Absolute request URLs are primarily useful in tests and direct HTTP clients.
	if req.URL != nil && req.URL.IsAbs() && req.URL.Scheme != "" && req.URL.Host != "" {
		return req.URL.Scheme + "://" + req.URL.Host
	}

	// In Encore Cloud the raw handler may see the underlying Cloud Run host.
	// Encore's runtime metadata is the authoritative public API base URL and
	// also respects environment custom domains.
	if origin := encoreAPIOrigin(); origin != "" {
		return origin
	}

	scheme := "https"
	if forwarded := strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	} else if req.TLS != nil {
		scheme = "https"
	} else if strings.HasPrefix(req.Host, "localhost") || strings.HasPrefix(req.Host, "127.0.0.1") || strings.HasPrefix(req.Host, "[::1]") {
		scheme = "http"
	}

	host := strings.TrimSpace(strings.Split(req.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = req.Host
	}
	return scheme + "://" + host
}

func protectedResourceURL(req *http.Request) string {
	return requestOrigin(req) + "/.well-known/oauth-protected-resource"
}

func oauthChallenge(req *http.Request) string {
	return fmt.Sprintf(`Bearer resource_metadata="%s", scope="%s"`, protectedResourceURL(req), oauthScopeMCP)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeProtectedResourceMetadata(w http.ResponseWriter, req *http.Request) {
	origin := requestOrigin(req)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 origin + "/mcp",
		"resource_name":            "Tensorlake MCP",
		"authorization_servers":    []string{origin},
		"scopes_supported":         []string{oauthScopeMCP, oauthScopeOffline},
		"bearer_methods_supported": []string{"header"},
	})
}

// OAuthProtectedResource publishes RFC 9728 metadata for MCP OAuth discovery.
//
//encore:api public raw path=/.well-known/oauth-protected-resource
func OAuthProtectedResource(w http.ResponseWriter, req *http.Request) {
	writeProtectedResourceMetadata(w, req)
}

// OAuthProtectedResourceMCP publishes the path-specific RFC 9728 metadata form.
//
//encore:api public raw path=/.well-known/oauth-protected-resource/mcp
func OAuthProtectedResourceMCP(w http.ResponseWriter, req *http.Request) {
	writeProtectedResourceMetadata(w, req)
}

func writeAuthorizationServerMetadata(w http.ResponseWriter, req *http.Request) {
	origin := requestOrigin(req)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": origin,
		"authorization_response_iss_parameter_supported": true,
		"authorization_endpoint":                         origin + "/oauth/authorize",
		"token_endpoint":                                 origin + "/oauth/token",
		"registration_endpoint":                          origin + "/oauth/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"scopes_supported":                               []string{oauthScopeMCP, oauthScopeOffline},
		"client_id_metadata_document_supported":          true,
	})
}

// OAuthAuthorizationServer publishes RFC 8414 authorization-server metadata.
//
//encore:api public raw path=/.well-known/oauth-authorization-server
func OAuthAuthorizationServer(w http.ResponseWriter, req *http.Request) {
	writeAuthorizationServerMetadata(w, req)
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateRedirectURIs(uris []string) error {
	if len(uris) == 0 {
		return errors.New("redirect_uris is required")
	}
	for _, raw := range uris {
		if !validRedirectURI(raw) {
			return fmt.Errorf("unsupported redirect_uri %q", raw)
		}
	}
	return nil
}

func redirectAllowed(client *oauthClient, redirectURI string) bool {
	for _, allowed := range client.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func scopeAllowed(scope string) bool {
	for _, item := range strings.Fields(scope) {
		if item != oauthScopeMCP && item != oauthScopeOffline {
			return false
		}
	}
	return true
}

func scopeContains(scope, wanted string) bool {
	for _, item := range strings.Fields(scope) {
		if item == wanted {
			return true
		}
	}
	return false
}

func validateResource(req *http.Request, resource string) bool {
	return resource == "" || resource == requestOrigin(req)+"/mcp"
}

func loadRegisteredOAuthClient(ctx context.Context, clientID string) (*oauthClient, error) {
	var name string
	var raw []byte
	err := db.QueryRow(ctx, "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = $1", clientID).Scan(&name, &raw)
	if err != nil {
		return nil, err
	}
	var redirectURIs []string
	if err := json.Unmarshal(raw, &redirectURIs); err != nil {
		return nil, err
	}
	return &oauthClient{ID: clientID, Name: name, RedirectURIs: redirectURIs}, nil
}

func loadChatGPTCIMDClient(ctx context.Context, clientID string) (*oauthClient, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "chatgpt.com") {
		return nil, errors.New("unsupported client metadata URL")
	}
	if !(u.Path == "/oauth/client.json" || (strings.HasPrefix(u.Path, "/oauth/") && strings.HasSuffix(u.Path, "/client.json"))) {
		return nil, errors.New("unsupported ChatGPT client metadata path")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("invalid client metadata URL")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("client metadata returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var metadata clientMetadataDocument
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode client metadata: %w", err)
	}
	if metadata.ClientID != "" && metadata.ClientID != clientID {
		return nil, errors.New("client metadata client_id mismatch")
	}
	supportsNone := metadata.TokenEndpointAuthMethod == "none"
	for _, method := range metadata.TokenEndpointAuthMethodsSupported {
		if method == "none" {
			supportsNone = true
			break
		}
	}
	if !supportsNone {
		return nil, errors.New("OAuth client does not support token_endpoint_auth_method=none")
	}
	if err := validateRedirectURIs(metadata.RedirectURIs); err != nil {
		return nil, err
	}
	return &oauthClient{ID: clientID, Name: metadata.ClientName, RedirectURIs: metadata.RedirectURIs}, nil
}

func loadOAuthClient(ctx context.Context, clientID string) (*oauthClient, error) {
	if strings.HasPrefix(clientID, "https://") {
		return loadChatGPTCIMDClient(ctx, clientID)
	}
	return loadRegisteredOAuthClient(ctx, clientID)
}

type oauthRegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
}

// OAuthRegister supports RFC 7591 dynamic client registration for legacy MCP clients.
// ChatGPT uses Client ID Metadata Documents when available.
//
//encore:api public raw path=/oauth/register
func OAuthRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
	var in oauthRegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON request")
		return
	}
	if in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != "none" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "only token_endpoint_auth_method=none is supported")
		return
	}
	if err := validateRedirectURIs(in.RedirectURIs); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
		return
	}
	clientID, err := randomOpaque(oauthClientPrefix, 24)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate client id")
		return
	}
	raw, _ := json.Marshal(in.RedirectURIs)
	if _, err := db.Exec(req.Context(), "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, $2, $3::jsonb)", clientID, strings.TrimSpace(in.ClientName), string(raw)); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to register OAuth client")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_name":                in.ClientName,
		"redirect_uris":              in.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
