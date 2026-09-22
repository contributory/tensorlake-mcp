package tensorlake

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sixt/tensorlake-go"
)

type ListSandboxesInput struct {
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Status string `json:"status,omitempty"`
}

type SandboxSummary struct {
	ID        string                   `json:"id"`
	Name      string                   `json:"name,omitempty"`
	Status    tensorlake.SandboxStatus `json:"status"`
	CreatedAt int64                    `json:"created_at"`
	Timeout   int64                    `json:"timeout_secs"`
	IsPrimary bool                     `json:"is_primary"`
}

type ListSandboxesOutput struct {
	Sandboxes  []SandboxSummary `json:"sandboxes"`
	PrevCursor string           `json:"prev_cursor,omitempty"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func (s *server) ListSandboxes(ctx context.Context, _ *mcp.CallToolRequest, in *ListSandboxesInput) (*mcp.CallToolResult, any, error) {
	if result := s.oauthRequiredResult(ctx); result != nil {
		return result, nil, nil
	}

	limit := in.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	resp, err := s.tl.ListSandboxes(ctx, &tensorlake.ListSandboxesRequest{
		Limit:  limit,
		Cursor: strings.TrimSpace(in.Cursor),
		Status: strings.TrimSpace(in.Status),
	})
	if err != nil {
		return newToolResultError(fmt.Errorf("failed to list Tensorlake sandboxes: %w", err))
	}

	primaryID, err := loadPrimarySandboxID(ctx, s.tenantID)
	if err != nil {
		return newToolResultError(fmt.Errorf("failed to load primary sandbox setting: %w", err))
	}

	out := &ListSandboxesOutput{
		Sandboxes:  make([]SandboxSummary, 0, len(resp.Sandboxes)),
		PrevCursor: resp.PrevCursor,
		NextCursor: resp.NextCursor,
	}
	for _, sandbox := range resp.Sandboxes {
		out.Sandboxes = append(out.Sandboxes, SandboxSummary{
			ID:        sandbox.Id,
			Name:      sandbox.Name,
			Status:    sandbox.Status,
			CreatedAt: sandbox.CreatedAt,
			Timeout:   sandbox.TimeoutSecs,
			IsPrimary: sandbox.Id == primaryID,
		})
	}
	return newToolResultJSON(out)
}

type SetSandboxInput struct {
	SandboxID string `json:"sandbox_id"`
}

type SetSandboxOutput struct {
	SandboxID string                   `json:"sandbox_id"`
	Name      string                   `json:"name,omitempty"`
	Status    tensorlake.SandboxStatus `json:"status"`
	Message   string                   `json:"message"`
}

func (s *server) SetSandbox(ctx context.Context, _ *mcp.CallToolRequest, in *SetSandboxInput) (*mcp.CallToolResult, any, error) {
	if result := s.oauthRequiredResult(ctx); result != nil {
		return result, nil, nil
	}

	sandboxID := strings.TrimSpace(in.SandboxID)
	if sandboxID == "" {
		return newToolResultError(fmt.Errorf("sandbox_id is required"))
	}

	info, err := s.tl.GetSandbox(ctx, sandboxID)
	if err != nil {
		return newToolResultError(fmt.Errorf("failed to get sandbox %q: %w", sandboxID, err))
	}
	if _, err := setPrimarySandboxID(ctx, s.apiKey, sandboxID); err != nil {
		return newToolResultError(fmt.Errorf("failed to persist primary sandbox: %w", err))
	}

	s.sandboxMu.Lock()
	changed := s.sandboxID != sandboxID
	s.sandboxID = sandboxID
	s.sandboxMu.Unlock()
	if changed {
		s.homeMu.Lock()
		s.homeDir = ""
		s.homeMu.Unlock()
	}

	return newToolResultJSON(&SetSandboxOutput{
		SandboxID: sandboxID,
		Name:      info.Name,
		Status:    info.Status,
		Message:   "Primary MCP sandbox updated. Normal tools will use this sandbox until it is changed again.",
	})
}
