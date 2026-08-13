// Copyright (c) 2026 Probo Inc <hello@probo.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package mcp_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/e2e/internal/testutil"
)

func TestMCP_MalaysiaPDPAScannerFinding_IngestIsIdempotent(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	mc := testutil.NewMCPClient(t, owner)
	input := map[string]any{
		"organization_id": owner.GetOrganizationID().String(),
		"external_id":     "mcp-scanner-finding-001",
		"source":          "openlist",
		"check_key":       "TLS",
		"severity":        "CRITICAL",
		"summary":         "Legacy TLS protocol is enabled",
		"evidence":        `{"protocol":"TLSv1.0"}`,
		"observed_at":     time.Date(2026, time.August, 12, 4, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"rule_version":    "scanner-rules-2026.08",
		"rule_source":     "https://scanner.example/rules/tls",
	}

	type result struct {
		Created        bool `json:"created"`
		ScannerFinding struct {
			ID       string `json:"id"`
			Evidence string `json:"evidence"`
		} `json:"scanner_finding"`
		Finding struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			Priority string `json:"priority"`
		} `json:"finding"`
	}

	var created result
	mc.CallToolInto("ingestMalaysiaPDPAScannerFinding", input, &created)
	assert.True(t, created.Created)
	require.NotEmpty(t, created.ScannerFinding.ID)
	require.NotEmpty(t, created.Finding.ID)
	assert.Equal(t, "MAJOR_NONCONFORMITY", created.Finding.Kind)
	assert.Equal(t, "HIGH", created.Finding.Priority)
	assert.JSONEq(t, input["evidence"].(string), created.ScannerFinding.Evidence)

	var updated result
	mc.CallToolInto("ingestMalaysiaPDPAScannerFinding", input, &updated)
	assert.False(t, updated.Created)
	assert.Equal(t, created.ScannerFinding.ID, updated.ScannerFinding.ID)
	assert.Equal(t, created.Finding.ID, updated.Finding.ID)
}

func TestMCP_MalaysiaPDPAScannerFinding_PrivacyScopeEnforcement(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	input := map[string]any{
		"organization_id": owner.GetOrganizationID().String(),
		"external_id":     "mcp-oauth-scanner-finding-001",
		"source":          "openlist",
		"check_key":       "MFA",
		"severity":        "MEDIUM",
		"summary":         "A privileged account does not require MFA",
		"evidence":        `{"account_type":"privileged"}`,
		"observed_at":     time.Date(2026, time.August, 12, 5, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"rule_version":    "scanner-rules-2026.08",
		"rule_source":     "https://scanner.example/rules/mfa",
	}

	readToken := owner.CreateOAuth2AccessToken("e2e-scanner-privacy-read", []string{"v1:privacy:read"})
	readClient := testutil.NewMCPClientWithAccessToken(t, owner, readToken)
	message := readClient.CallToolExpectToolError("ingestMalaysiaPDPAScannerFinding", input)
	assert.Equal(t, "insufficient scope", message)

	writeToken := owner.CreateOAuth2AccessToken("e2e-scanner-privacy-write", []string{"v1:privacy"})
	writeClient := testutil.NewMCPClientWithAccessToken(t, owner, writeToken)

	var result struct {
		Created bool `json:"created"`
	}
	writeClient.CallToolInto("ingestMalaysiaPDPAScannerFinding", input, &result)
	assert.True(t, result.Created)
}
