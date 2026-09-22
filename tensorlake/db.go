package tensorlake

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"encore.dev/storage/sqldb"
)

var db = sqldb.NewDatabase("tensorlake", sqldb.DatabaseConfig{
	Migrations: "./migrations",
})

type accountRecord struct {
	TenantID         string
	TensorlakeAPIKey string
	PrimarySandboxID string
}

func tenantIDForAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(apiKey)))
	return hex.EncodeToString(sum[:])
}

func upsertAccount(ctx context.Context, apiKey string) (string, error) {
	apiKey = strings.TrimSpace(apiKey)
	tenantID := tenantIDForAPIKey(apiKey)
	_, err := db.Exec(ctx, `
		INSERT INTO tensorlake_accounts (tenant_id, tensorlake_api_key)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE
		SET tensorlake_api_key = EXCLUDED.tensorlake_api_key,
		    updated_at = NOW()
	`, tenantID, apiKey)
	if err != nil {
		return "", err
	}
	return tenantID, nil
}

func loadAccountByTenantID(ctx context.Context, tenantID string) (*accountRecord, error) {
	var account accountRecord
	var sandboxID sql.NullString
	err := db.QueryRow(ctx, `
		SELECT tenant_id, tensorlake_api_key, primary_sandbox_id
		FROM tensorlake_accounts
		WHERE tenant_id = $1
	`, tenantID).Scan(&account.TenantID, &account.TensorlakeAPIKey, &sandboxID)
	if err != nil {
		return nil, err
	}
	if sandboxID.Valid {
		account.PrimarySandboxID = sandboxID.String
	}
	return &account, nil
}

func loadPrimarySandboxID(ctx context.Context, tenantID string) (string, error) {
	var sandboxID sql.NullString
	err := db.QueryRow(ctx, `
		SELECT primary_sandbox_id
		FROM tensorlake_accounts
		WHERE tenant_id = $1
	`, tenantID).Scan(&sandboxID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !sandboxID.Valid {
		return "", nil
	}
	return strings.TrimSpace(sandboxID.String), nil
}

func setPrimarySandboxID(ctx context.Context, apiKey, sandboxID string) (string, error) {
	tenantID, err := upsertAccount(ctx, apiKey)
	if err != nil {
		return "", err
	}
	_, err = db.Exec(ctx, `
		UPDATE tensorlake_accounts
		SET primary_sandbox_id = $2,
		    updated_at = NOW()
		WHERE tenant_id = $1
	`, tenantID, strings.TrimSpace(sandboxID))
	if err != nil {
		return "", err
	}
	return tenantID, nil
}
