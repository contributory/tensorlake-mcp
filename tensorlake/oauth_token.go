package tensorlake

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	oauthAccessTTL  = time.Hour
	oauthRefreshTTL = 30 * 24 * time.Hour
)

type oauthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func createOAuthSession(req *http.Request, tenantID, clientID, scope string) (*oauthTokenResponse, error) {
	accessToken, err := randomOpaque(oauthAccessTokenPrefix, 32)
	if err != nil {
		return nil, err
	}
	refreshToken, err := randomOpaque(oauthRefreshTokenPrefix, 32)
	if err != nil {
		return nil, err
	}
	sessionID, err := randomOpaque("tlmcp_session_", 24)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	_, err = db.Exec(req.Context(),
		"INSERT INTO oauth_sessions (session_id, tenant_id, client_id, scope, access_token_hash, refresh_token_hash, access_expires_at, refresh_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
		sessionID, tenantID, clientID, scope, tokenHash(accessToken), tokenHash(refreshToken), now.Add(oauthAccessTTL), now.Add(oauthRefreshTTL),
	)
	if err != nil {
		return nil, err
	}
	return &oauthTokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(oauthAccessTTL.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func exchangeAuthorizationCode(w http.ResponseWriter, req *http.Request, clientID string) {
	code := strings.TrimSpace(req.FormValue("code"))
	redirectURI := strings.TrimSpace(req.FormValue("redirect_uri"))
	verifier := strings.TrimSpace(req.FormValue("code_verifier"))
	resource := strings.TrimSpace(req.FormValue("resource"))
	if code == "" || clientID == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, client_id, redirect_uri and code_verifier are required")
		return
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid PKCE verifier")
		return
	}
	if !validateResource(req, resource) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not identify this MCP endpoint")
		return
	}

	var tenantID, storedClientID, storedRedirectURI, scope, storedResource, challenge string
	var expiresAt time.Time
	expectedChallenge := pkceS256(verifier)
	err := db.QueryRow(req.Context(),
		"DELETE FROM oauth_authorization_codes WHERE code_hash=$1 AND client_id=$2 AND redirect_uri=$3 AND code_challenge=$4 AND expires_at > NOW() AND ($5 = '' OR resource = '' OR resource = $5) RETURNING tenant_id, client_id, redirect_uri, scope, resource, code_challenge, expires_at",
		tokenHash(code), clientID, redirectURI, expectedChallenge, resource,
	).Scan(&tenantID, &storedClientID, &storedRedirectURI, &scope, &storedResource, &challenge, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid, expired, or already used")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to consume authorization code")
		return
	}
	if clientID != storedClientID || redirectURI != storedRedirectURI || expectedChallenge != challenge {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code binding or PKCE verification failed")
		return
	}
	if storedResource != "" && resource != "" && resource != storedResource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource differs from authorization request")
		return
	}

	response, err := createOAuthSession(req, tenantID, clientID, scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue OAuth tokens")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func rotateRefreshToken(w http.ResponseWriter, req *http.Request, clientID string) {
	refreshToken := strings.TrimSpace(req.FormValue("refresh_token"))
	resource := strings.TrimSpace(req.FormValue("resource"))
	if refreshToken == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
		return
	}
	if !validateResource(req, resource) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not identify this MCP endpoint")
		return
	}

	newAccessToken, err := randomOpaque(oauthAccessTokenPrefix, 32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}
	newRefreshToken, err := randomOpaque(oauthRefreshTokenPrefix, 32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}

	now := time.Now()
	var tenantID, storedClientID, scope string
	err = db.QueryRow(req.Context(),
		"UPDATE oauth_sessions SET access_token_hash=$1, refresh_token_hash=$2, access_expires_at=$3, refresh_expires_at=$4, updated_at=NOW() WHERE refresh_token_hash=$5 AND client_id=$6 AND refresh_expires_at > NOW() RETURNING tenant_id, client_id, scope",
		tokenHash(newAccessToken), tokenHash(newRefreshToken), now.Add(oauthAccessTTL), now.Add(oauthRefreshTTL), tokenHash(refreshToken), clientID,
	).Scan(&tenantID, &storedClientID, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to refresh OAuth tokens")
		return
	}
	if clientID != storedClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token does not belong to this client")
		return
	}

	writeJSON(w, http.StatusOK, &oauthTokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(oauthAccessTTL.Seconds()),
		RefreshToken: newRefreshToken,
		Scope:        scope,
	})
}

// OAuthToken exchanges authorization codes and rotates refresh tokens.
//
//encore:api public raw path=/oauth/token
func OAuthToken(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
	if err := req.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	clientID, err := authenticateTokenClient(req)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	switch req.FormValue("grant_type") {
	case "authorization_code":
		exchangeAuthorizationCode(w, req, clientID)
	case "refresh_token":
		rotateRefreshToken(w, req, clientID)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grants are authorization_code and refresh_token")
	}
}

func apiKeyForOAuthAccessToken(req *http.Request, token string) (string, error) {
	var apiKey, scope string
	err := db.QueryRow(req.Context(),
		"SELECT a.tensorlake_api_key, s.scope FROM oauth_sessions s JOIN tensorlake_accounts a ON a.tenant_id=s.tenant_id WHERE s.access_token_hash=$1 AND s.access_expires_at > NOW()",
		tokenHash(token),
	).Scan(&apiKey, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errInvalidAccessToken
	}
	if err != nil {
		return "", err
	}
	if !scopeContains(scope, oauthScopeMCP) {
		return "", errInvalidAccessToken
	}
	return apiKey, nil
}
