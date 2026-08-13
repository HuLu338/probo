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

package openlistscanner_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.gearno.de/kit/httpclient"
	"go.probo.inc/probo/pkg/malaysiapdpa/openlistscanner"
)

func TestClientGetScanReport(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/scans/42", r.URL.Path)
		assert.Equal(t, "scanner-secret", r.Header.Get("X-API-Key"))
		assert.Empty(t, r.URL.RawQuery)

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{
			"id": 42,
			"platform": "openlist",
			"scan_time": "2026-08-12T04:10:00Z",
			"target_path": "/etc/openlist/config.json",
			"total_score": 65,
			"triggered_rules_count": 1,
			"risks": [{"rule_id":"openlist-https-disabled","title":"HTTPS Not Enabled","severity":"high"}]
		}`)
	}))
	t.Cleanup(server.Close)

	client, err := openlistscanner.NewClient(
		server.URL+"/backend-api/..",
		"scanner-secret",
		5*time.Second,
		openlistscanner.WithHTTPClient(
			httpclient.DefaultClient(
				httpclient.WithSSRFProtection(),
				httpclient.WithSSRFAllowLoopback(),
			),
		),
	)
	require.NoError(t, err)

	report, err := client.GetScanReport(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, int64(42), report.ID)
	assert.Equal(t, "openlist", report.Platform)
	assert.Equal(t, 65, report.TotalScore)
	require.Len(t, report.Risks, 1)
	assert.Equal(t, "openlist-https-disabled", report.Risks[0].RuleID)
}

func TestClientGetScanReport_RejectsUnexpectedResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		statusCode    int
		body          string
		errorContains string
	}{
		{
			name:          "authentication failure",
			statusCode:    http.StatusUnauthorized,
			body:          `{"error":"unauthorized"}`,
			errorContains: "HTTP 401",
		},
		{
			name:          "invalid JSON",
			statusCode:    http.StatusOK,
			body:          `{`,
			errorContains: "cannot decode",
		},
		{
			name:          "mismatched report ID",
			statusCode:    http.StatusOK,
			body:          `{"id":43}`,
			errorContains: "report ID 43",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.statusCode)
					_, _ = fmt.Fprint(w, tt.body)
				}))
				t.Cleanup(server.Close)

				client, err := openlistscanner.NewClient(
					server.URL,
					"scanner-secret",
					5*time.Second,
					openlistscanner.WithHTTPClient(
						httpclient.DefaultClient(
							httpclient.WithSSRFProtection(),
							httpclient.WithSSRFAllowLoopback(),
						),
					),
				)
				require.NoError(t, err)

				_, err = client.GetScanReport(context.Background(), 42)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			},
		)
	}
}

func TestClientGetScanReport_DoesNotForwardAPIKeyThroughRedirect(t *testing.T) {
	t.Parallel()

	redirectTargetReached := make(chan struct{}, 1)
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectTargetReached <- struct{}{}
	}))
	t.Cleanup(redirectTarget.Close)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)

	client, err := openlistscanner.NewClient(server.URL, "scanner-secret", 5*time.Second)
	require.NoError(t, err)

	_, err = client.GetScanReport(context.Background(), 42)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 302")

	select {
	case <-redirectTargetReached:
		assert.Fail(t, "redirect target must not receive the scanner API key request")
	default:
	}
}

func TestNewClient_ValidatesConnectionDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		url    string
		apiKey string
	}{
		{name: "relative URL", url: "/scanner", apiKey: "secret"},
		{name: "URL credentials", url: "https://user@example.test", apiKey: "secret"},
		{name: "missing API key", url: "https://scanner.example.test", apiKey: ""},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				_, err := openlistscanner.NewClient(tt.url, tt.apiKey, time.Second)
				require.Error(t, err)
			},
		)
	}
}
