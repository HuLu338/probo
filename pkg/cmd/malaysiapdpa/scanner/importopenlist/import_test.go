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

package importopenlist

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/cli/config"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
	"go.probo.inc/probo/pkg/cmd/iostreams"
)

type capturedRequest struct {
	Method        string
	Path          string
	APIKey        string
	Authorization string
	Query         string
	Input         map[string]any
}

func TestNewCmdImportOpenList_ImportsScanReport(t *testing.T) {
	t.Parallel()

	scannerRequests := make(chan capturedRequest, 1)
	scanner := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scannerRequests <- capturedRequest{
				Method: r.Method,
				Path:   r.URL.Path,
				APIKey: r.Header.Get("X-API-Key"),
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "id": 42,
  "platform": "openlist",
  "scan_time": "2026-08-12T03:04:05Z",
  "target_path": "/srv/openlist/config.json",
  "total_score": 84,
  "triggered_rules_count": 1,
  "risks": [{
    "rule_id": "openlist-tls-skip-verify",
    "title": "TLS certificate verification is disabled",
    "severity": "high",
    "description": "The scanner accepts untrusted certificates.",
    "recommendation": "Enable certificate verification."
  }]
}`))
		}),
	)
	t.Cleanup(scanner.Close)

	proboRequests := make(chan capturedRequest, 1)
	probo := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				Query     string `json:"query"`
				Variables struct {
					Input map[string]any `json:"input"`
				} `json:"variables"`
			}

			_ = json.NewDecoder(r.Body).Decode(&request)

			proboRequests <- capturedRequest{
				Method:        r.Method,
				Path:          r.URL.Path,
				Authorization: r.Header.Get("Authorization"),
				Query:         request.Query,
				Input:         request.Variables.Input,
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "data": {
    "ingestMalaysiaPDPAScannerFinding": {
      "created": true,
      "scannerFinding": {
        "id": "scanner-finding-id",
        "externalId": "customer-a-openlist:openlist-tls-skip-verify"
      },
      "finding": {
        "id": "finding-id",
        "referenceId": "FND-42",
        "priority": "HIGH",
        "status": "OPEN"
      }
    }
  }
}`))
		}),
	)
	t.Cleanup(probo.Close)

	streams, out, _ := iostreams.Test()
	cfg := &config.Config{HTTPTimeout: "5s"}
	hostConfig := &config.HostConfig{
		Token:        "probo-token",
		Organization: "organization-id",
	}
	factory := &cmdutil.Factory{
		IOStreams: streams,
		Config: func() (*config.Config, error) {
			return cfg, nil
		},
	}
	getenv := func(key string) string {
		if key == "OPENLIST_API_KEY" {
			return "scanner-api-key"
		}

		return ""
	}
	cmd := newCmdImportOpenList(
		factory,
		getenv,
		func(*config.Config) (string, *config.HostConfig, error) {
			return probo.URL, hostConfig, nil
		},
	)
	cmd.SetArgs([]string{
		"42",
		"--scanner-url", scanner.URL,
		"--target-id", "customer-a-openlist",
		"--rule-version", "2026.08",
		"--rule-source", "https://scanner.example/rules/openlist",
		"--output", "json",
	})

	err := cmd.Execute()

	require.NoError(t, err)

	scannerRequest := <-scannerRequests
	assert.Equal(t, http.MethodGet, scannerRequest.Method)
	assert.Equal(t, "/scans/42", scannerRequest.Path)
	assert.Equal(t, "scanner-api-key", scannerRequest.APIKey)

	proboRequest := <-proboRequests
	assert.Equal(t, http.MethodPost, proboRequest.Method)
	assert.Equal(t, "/api/console/v1/graphql", proboRequest.Path)
	assert.Equal(t, "Bearer probo-token", proboRequest.Authorization)
	assert.Contains(t, proboRequest.Query, "ingestMalaysiaPDPAScannerFinding")
	assert.Equal(t, "organization-id", proboRequest.Input["organizationId"])
	assert.Equal(t, "customer-a-openlist:openlist-tls-skip-verify", proboRequest.Input["externalId"])
	assert.Equal(t, "openlist", proboRequest.Input["source"])
	assert.Equal(t, "TLS", proboRequest.Input["checkKey"])
	assert.Equal(t, "HIGH", proboRequest.Input["severity"])
	assert.Equal(t, "2026.08", proboRequest.Input["ruleVersion"])
	assert.Equal(t, "https://scanner.example/rules/openlist", proboRequest.Input["ruleSource"])
	assert.Equal(t, "2026-08-12T03:04:05Z", proboRequest.Input["observedAt"])
	assert.NotContains(t, proboRequest.Input["evidence"], "/srv/openlist/config.json")

	var result importResult
	require.NoError(t, json.NewDecoder(strings.NewReader(out.String())).Decode(&result))
	assert.Equal(t, int64(42), result.ScanReportID)
	assert.Equal(t, 1, result.Imported)
	require.Len(t, result.Findings, 1)
	assert.True(t, result.Findings[0].Created)
	assert.Equal(t, "FND-42", result.Findings[0].ReferenceID)
}
