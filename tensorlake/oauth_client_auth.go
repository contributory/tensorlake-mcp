package tensorlake

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const privateKeyJWTAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf,omitempty"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

func decodeJWTPart(value string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func jwtAudienceContains(raw json.RawMessage, wanted ...string) bool {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		for _, candidate := range wanted {
			if single == candidate {
				return true
			}
		}
		return false
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false
	}
	for _, value := range many {
		for _, candidate := range wanted {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func rsaPublicKeyFromJWK(key jwk) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" || key.N == "" || key.E == "" {
		return nil, errors.New("unsupported JWK")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func fetchChatGPTJWKS(ctx context.Context) (*jwksDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/oauth/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch ChatGPT JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("ChatGPT JWKS returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return nil, err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func verifyChatGPTClientAssertion(ctx context.Context, req *http.Request, assertion, expectedClientID string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed client assertion")
	}

	var header jwtHeader
	var claims jwtClaims
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return "", errors.New("invalid client assertion header")
	}
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return "", errors.New("invalid client assertion claims")
	}
	if header.Alg != "RS256" || header.Kid == "" {
		return "", errors.New("unsupported client assertion algorithm")
	}

	clientID := strings.TrimSpace(expectedClientID)
	if clientID == "" {
		clientID = strings.TrimSpace(claims.Iss)
	}
	if clientID == "" || claims.Iss != clientID || claims.Sub != clientID {
		return "", errors.New("client assertion identity mismatch")
	}
	if _, err := loadChatGPTCIMDClient(ctx, clientID); err != nil {
		return "", fmt.Errorf("untrusted ChatGPT client metadata: %w", err)
	}

	now := time.Now().Unix()
	if claims.Exp <= now || claims.Exp > now+10*60 {
		return "", errors.New("client assertion is expired or has excessive lifetime")
	}
	if claims.Nbf != 0 && claims.Nbf > now+30 {
		return "", errors.New("client assertion is not active yet")
	}
	origin := requestOrigin(req)
	if !jwtAudienceContains(claims.Aud, origin+"/oauth/token", origin) {
		return "", errors.New("client assertion audience mismatch")
	}

	doc, err := fetchChatGPTJWKS(ctx)
	if err != nil {
		return "", err
	}
	var publicKey *rsa.PublicKey
	for _, key := range doc.Keys {
		if key.Kid != header.Kid {
			continue
		}
		if key.Alg != "" && key.Alg != "RS256" {
			continue
		}
		publicKey, err = rsaPublicKeyFromJWK(key)
		if err != nil {
			return "", err
		}
		break
	}
	if publicKey == nil {
		return "", errors.New("client assertion signing key not found")
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("invalid client assertion signature encoding")
	}
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return "", errors.New("invalid client assertion signature")
	}
	return clientID, nil
}

func authenticateTokenClient(req *http.Request) (string, error) {
	clientID := strings.TrimSpace(req.FormValue("client_id"))
	assertion := strings.TrimSpace(req.FormValue("client_assertion"))
	assertionType := strings.TrimSpace(req.FormValue("client_assertion_type"))

	if assertion != "" || assertionType != "" {
		if assertion == "" || assertionType != privateKeyJWTAssertionType {
			return "", errors.New("invalid private_key_jwt client authentication")
		}
		return verifyChatGPTClientAssertion(req.Context(), req, assertion, clientID)
	}

	if clientID == "" {
		return "", errors.New("client_id is required")
	}
	if strings.HasPrefix(clientID, "https://") {
		if _, err := loadChatGPTCIMDClient(req.Context(), clientID); err != nil {
			return "", err
		}
		return clientID, nil
	}
	if _, err := loadRegisteredOAuthClient(req.Context(), clientID); err != nil {
		return "", err
	}
	return clientID, nil
}
