package tensorlake

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	tl "github.com/sixt/tensorlake-go"
)

type authorizationRequest struct {
	ClientID      string
	RedirectURI   string
	ResponseType  string
	Scope         string
	State         string
	CodeChallenge string
	Resource      string
}

func readAuthorizationRequest(req *http.Request) authorizationRequest {
	return authorizationRequest{
		ClientID:      strings.TrimSpace(req.FormValue("client_id")),
		RedirectURI:   strings.TrimSpace(req.FormValue("redirect_uri")),
		ResponseType:  strings.TrimSpace(req.FormValue("response_type")),
		Scope:         strings.TrimSpace(req.FormValue("scope")),
		State:         req.FormValue("state"),
		CodeChallenge: strings.TrimSpace(req.FormValue("code_challenge")),
		Resource:      strings.TrimSpace(req.FormValue("resource")),
	}
}

func validateAuthorizationRequest(ctx context.Context, req *http.Request, in authorizationRequest) (*oauthClient, authorizationRequest, error) {
	if in.ClientID == "" {
		return nil, in, fmt.Errorf("client_id is required")
	}
	if in.ResponseType != "code" {
		return nil, in, fmt.Errorf("response_type must be code")
	}
	if in.RedirectURI == "" {
		return nil, in, fmt.Errorf("redirect_uri is required")
	}
	if req.FormValue("code_challenge_method") != "S256" || in.CodeChallenge == "" {
		return nil, in, fmt.Errorf("PKCE S256 is required")
	}
	if in.Scope == "" {
		in.Scope = oauthScopeMCP
	}
	if !scopeAllowed(in.Scope) || !scopeContains(in.Scope, oauthScopeMCP) {
		return nil, in, fmt.Errorf("scope must include mcp and may only contain supported scopes")
	}
	if !validateResource(req, in.Resource) {
		return nil, in, fmt.Errorf("resource must identify this MCP endpoint")
	}
	client, err := loadOAuthClient(ctx, in.ClientID)
	if err != nil {
		return nil, in, fmt.Errorf("unknown OAuth client: %w", err)
	}
	if !redirectAllowed(client, in.RedirectURI) {
		return nil, in, fmt.Errorf("redirect_uri is not registered for this client")
	}
	return client, in, nil
}

var authorizePage = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect Tensorlake MCP</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: Canvas; color: CanvasText; }
    main { width: min(440px, calc(100vw - 32px)); border: 1px solid color-mix(in srgb, CanvasText 18%, transparent); border-radius: 16px; padding: 24px; box-sizing: border-box; }
    h1 { margin: 0 0 10px; font-size: 1.4rem; }
    p { line-height: 1.5; opacity: .82; }
    label { display: block; font-weight: 650; margin: 20px 0 8px; }
    input[type=password] { width: 100%; box-sizing: border-box; padding: 12px; border-radius: 10px; border: 1px solid color-mix(in srgb, CanvasText 24%, transparent); font: inherit; }
    button { width: 100%; margin-top: 16px; padding: 12px; border: 0; border-radius: 10px; font: inherit; font-weight: 700; cursor: pointer; }
    .client { font-size: .9rem; opacity: .68; word-break: break-word; }
  </style>
</head>
<body>
<main>
  <h1>Connect Tensorlake MCP</h1>
  <p>Enter your Tensorlake API key. The key is stored by this MCP service in its Encore database and is never returned to the OAuth client.</p>
  <p class="client">Connecting client: {{.ClientName}}</p>
  <form method="post" autocomplete="off">
    <input type="hidden" name="client_id" value="{{.Request.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.Request.RedirectURI}}">
    <input type="hidden" name="response_type" value="{{.Request.ResponseType}}">
    <input type="hidden" name="scope" value="{{.Request.Scope}}">
    <input type="hidden" name="state" value="{{.Request.State}}">
    <input type="hidden" name="code_challenge" value="{{.Request.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="resource" value="{{.Request.Resource}}">
    <label for="api_key">Tensorlake API key</label>
    <input id="api_key" name="tensorlake_api_key" type="password" required autofocus spellcheck="false" autocomplete="off">
    <button type="submit">Authorize</button>
  </form>
</main>
</body>
</html>`))

func renderAuthorizePage(w http.ResponseWriter, client *oauthClient, in authorizationRequest) {
	clientName := strings.TrimSpace(client.Name)
	if clientName == "" {
		clientName = client.ID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = authorizePage.Execute(w, map[string]any{
		"ClientName": clientName,
		"Request":    in,
	})
}

func validateTensorlakeAPIKey(ctx context.Context, apiKey string) error {
	s := newServer(apiKey)
	_, err := s.tl.ListSandboxes(ctx, &tl.ListSandboxesRequest{Limit: 1})
	return err
}

func completeAuthorization(w http.ResponseWriter, req *http.Request, in authorizationRequest) {
	apiKey := strings.TrimSpace(req.FormValue("tensorlake_api_key"))
	if apiKey == "" {
		http.Error(w, "Tensorlake API key is required", http.StatusBadRequest)
		return
	}
	if err := validateTensorlakeAPIKey(req.Context(), apiKey); err != nil {
		http.Error(w, "Tensorlake rejected this API key", http.StatusUnauthorized)
		return
	}
	tenantID, err := upsertAccount(req.Context(), apiKey)
	if err != nil {
		http.Error(w, "failed to store Tensorlake account", http.StatusInternalServerError)
		return
	}
	code, err := randomOpaque(oauthCodePrefix, 32)
	if err != nil {
		http.Error(w, "failed to create authorization code", http.StatusInternalServerError)
		return
	}
	expiresAt := time.Now().Add(10 * time.Minute)
	_, err = db.Exec(req.Context(),
		"INSERT INTO oauth_authorization_codes (code_hash, tenant_id, client_id, redirect_uri, scope, resource, code_challenge, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
		tokenHash(code), tenantID, in.ClientID, in.RedirectURI, in.Scope, in.Resource, in.CodeChallenge, expiresAt,
	)
	if err != nil {
		http.Error(w, "failed to store authorization code", http.StatusInternalServerError)
		return
	}

	redirect, err := url.Parse(in.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	query := redirect.Query()
	query.Set("code", code)
	if in.State != "" {
		query.Set("state", in.State)
	}
	query.Set("iss", requestOrigin(req))
	redirect.RawQuery = query.Encode()
	http.Redirect(w, req, redirect.String(), http.StatusFound)
}

// OAuthAuthorize asks the user for a Tensorlake API key and issues an OAuth authorization code.
//
//encore:api public raw path=/oauth/authorize
func OAuthAuthorize(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.Method == http.MethodPost {
		req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}

	in := readAuthorizationRequest(req)
	client, normalized, err := validateAuthorizationRequest(req.Context(), req, in)
	if err != nil {
		http.Error(w, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
		return
	}
	in = normalized

	if req.Method == http.MethodGet {
		renderAuthorizePage(w, client, in)
		return
	}
	completeAuthorization(w, req, in)
}
