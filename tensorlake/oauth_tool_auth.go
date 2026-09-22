package tensorlake

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type oauthChallengeContextKey struct{}

func (s *server) oauthRequiredResult(ctx context.Context) *mcp.CallToolResult {
	if s.apiKey != "" {
		return nil
	}
	challenge, _ := ctx.Value(oauthChallengeContextKey{}).(string)
	if challenge == "" {
		challenge = `Bearer error="invalid_token", error_description="OAuth authorization required"`
	} else {
		challenge += `, error="invalid_token", error_description="OAuth authorization required"`
	}
	return &mcp.CallToolResult{
		Meta: mcp.Meta{
			"mcp/www_authenticate": []string{challenge},
		},
		Content: []mcp.Content{
			&mcp.TextContent{Text: "Authentication required. Connect your Tensorlake account to continue."},
		},
		IsError: true,
	}
}
