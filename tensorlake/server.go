// Copyright 2026 SIXT SE
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tensorlake

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"encore.app/tensorlake/internal/mimetype"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sixt/tensorlake-go"
)

type server struct {
	tl          *tensorlake.Client
	apiKey      string
	tenantID    string
	sandboxID   string
	sandboxMu   sync.Mutex
	homeDir     string
	homeMu      sync.Mutex
	bgMu        sync.Mutex
	bgProcesses map[string]*bgProcess
	bgCounter   int
}

func newServer(apiKey string) *server {
	return &server{
		apiKey:   apiKey,
		tenantID: tenantIDForAPIKey(apiKey),
		tl: tensorlake.NewClient(
			tensorlake.WithBaseURL(tlAPIBaseURL),
			tensorlake.WithAPIKey(apiKey),
			tensorlake.WithSandboxAPIBaseURL(tlSandboxAPIBaseURL),
			tensorlake.WithSandboxProxyBaseURL(tlSandboxProxyBaseURL),
		),
		bgProcesses: make(map[string]*bgProcess),
	}
}

// ensureSandbox returns the persisted primary sandbox ID for this Tensorlake account.
// The Encore database is the source of truth so sandbox changes are immediately
// visible across horizontally scaled MCP instances.
func (s *server) ensureSandbox(ctx context.Context) (string, error) {
	id, err := loadPrimarySandboxID(ctx, s.tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to load primary Tensorlake sandbox: %w", err)
	}
	if id == "" {
		return "", fmt.Errorf("no primary Tensorlake sandbox is configured; use list_sandboxes only if discovery is needed, then call set_sandbox once")
	}

	s.sandboxMu.Lock()
	changed := s.sandboxID != id
	s.sandboxID = id
	s.sandboxMu.Unlock()

	if changed {
		s.homeMu.Lock()
		s.homeDir = ""
		s.homeMu.Unlock()
	}
	return id, nil
}

// sandboxHomeDir resolves and caches the sandbox user's $HOME directory.
func (s *server) sandboxHomeDir(ctx context.Context) (string, error) {
	s.homeMu.Lock()
	defer s.homeMu.Unlock()

	if s.homeDir != "" {
		return s.homeDir, nil
	}

	_, stdout, stderr, err := s.runCommand(ctx, `printf '%s' "$HOME"`, 10, "/")
	if err != nil {
		return "", fmt.Errorf("failed to resolve sandbox home directory: %w", err)
	}

	home := strings.TrimSpace(stdout)
	if home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("failed to resolve sandbox home directory: stdout=%q stderr=%q", stdout, stderr)
	}

	s.homeDir = home
	return home, nil
}

const maxOutputBytes = 100 * 1024 // 100KB

func truncateOutput(s string) string {
	if len(s) <= maxOutputBytes {
		return s
	}
	half := maxOutputBytes / 2
	head := s[:half]
	tail := s[len(s)-half:]
	omitted := len(s) - maxOutputBytes
	return head + fmt.Sprintf("\n\n... [%d bytes truncated] ...\n\n", omitted) + tail
}

// runCommand executes a shell command in the sandbox and returns its output.
// onProgress is called periodically while the command runs (can be nil).
func (s *server) runCommand(ctx context.Context, command string, timeoutSec int, workingDir string, onProgress ...func(elapsed, total int)) (exitCode int, stdout, stderr string, err error) {
	sandboxID, err := s.ensureSandbox(ctx)
	if err != nil {
		return -1, "", "", err
	}

	var progressFn func(elapsed, total int)
	if len(onProgress) > 0 {
		progressFn = onProgress[0]
	}

	timeout := cmp.Or(timeoutSec, 30)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Tensorlake starts processes at / when no working directory is supplied.
	// Make the sandbox user's $HOME the default workspace instead.
	if workingDir == "" {
		command = `cd "$HOME" && ` + command
	}

	// Starting a process is also Tensorlake's wake-up trigger for a suspended
	// sandbox. Do not inspect or manage sandbox lifecycle state here; keep
	// retrying process creation until Tensorlake accepts it or the command
	// timeout expires.
	var proc *tensorlake.ProcessInfo
	for {
		req := &tensorlake.StartProcessRequest{
			Command:    "/bin/sh",
			Args:       []string{"-c", command},
			StdoutMode: tensorlake.OutputModeCapture,
			StderrMode: tensorlake.OutputModeCapture,
		}
		if wd := cmp.Or(workingDir, ""); wd != "" {
			req.WorkingDir = wd
		}
		proc, err = s.tl.StartProcess(ctx, sandboxID, req)
		if err == nil {
			break
		}

		select {
		case <-ctx.Done():
			return -1, "", "", fmt.Errorf("failed to start process before timeout: %w", err)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Poll until process exits, sending progress notifications if provided.
	elapsed := 0
	for {
		info, err := s.tl.GetProcess(ctx, sandboxID, proc.PID)
		if err != nil {
			return -1, "", "", fmt.Errorf("failed to get process status: %w", err)
		}
		if info.Status != tensorlake.ProcessStatusRunning {
			break
		}
		if progressFn != nil {
			elapsed++
			progressFn(elapsed, timeout)
		}
		select {
		case <-ctx.Done():
			_ = s.tl.KillProcess(context.Background(), sandboxID, proc.PID)
			return -1, "", "", fmt.Errorf("command timed out after %ds", timeout)
		case <-time.After(250 * time.Millisecond):
		}
	}

	// Collect output.
	stdoutResp, err := s.tl.GetProcessStdout(ctx, sandboxID, proc.PID)
	if err != nil {
		return -1, "", "", fmt.Errorf("failed to get stdout: %w", err)
	}
	stderrResp, err := s.tl.GetProcessStderr(ctx, sandboxID, proc.PID)
	if err != nil {
		return -1, "", "", fmt.Errorf("failed to get stderr: %w", err)
	}

	// Get final exit code.
	info, err := s.tl.GetProcess(ctx, sandboxID, proc.PID)
	if err != nil {
		return -1, truncateOutput(strings.Join(stdoutResp.Lines, "\n")),
			truncateOutput(strings.Join(stderrResp.Lines, "\n")), err
	}

	ec := 0
	if info.ExitCode != nil {
		ec = int(*info.ExitCode)
	}
	return ec, truncateOutput(strings.Join(stdoutResp.Lines, "\n")),
		truncateOutput(strings.Join(stderrResp.Lines, "\n")), nil
}

// CleanupSession clears process-local caches only. User-owned Tensorlake sandboxes
// and the persisted primary-sandbox selection are intentionally left untouched.
func (s *server) CleanupSession(_ context.Context) {
	s.sandboxMu.Lock()
	s.sandboxID = ""
	s.sandboxMu.Unlock()
	s.homeMu.Lock()
	s.homeDir = ""
	s.homeMu.Unlock()
}

// sendProgress sends a progress notification if a progress token is available.
func (s *server) sendProgress(ctx context.Context, req *mcp.CallToolRequest, progress float64, total float64, message string) {
	if req == nil || req.Session == nil {
		return
	}
	_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
		ProgressToken: req.Params.GetProgressToken(),
		Progress:      progress,
		Total:         total,
		Message:       message,
	})
}

func newToolResultJSON[T any](data T) (*mcp.CallToolResult, any, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return newToolResultError(fmt.Errorf("unable to marshal JSON: %w", err))
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(b)},
		},
	}, nil, nil
}

func newToolResultText(text string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}, nil, nil
}

func newToolResultError(err error) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: err.Error()},
		},
	}, nil, nil
}

// downloadFile downloads a file from a URL with optional authorization.
func downloadFile(ctx context.Context, url, authToken string) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download file: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	fileName := filepath.Base(url)
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if name, ok := strings.CutPrefix(cd, "attachment; filename="); ok {
			fileName = strings.Trim(name, "\"")
		}
	}
	if filepath.Ext(fileName) == "" {
		detectedExt, err := mimetype.DetectExtensionFromContentType(resp)
		if err != nil {
			return nil, "", fmt.Errorf("failed to detect extension: %w", err)
		}
		if detectedExt != "" {
			fileName = fileName + detectedExt
		}
	}

	return resp.Body, fileName, nil
}
