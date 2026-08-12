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

package openlistscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.gearno.de/kit/httpclient"
	"go.probo.inc/probo/pkg/version"
)

const (
	maxScanReportResponseBytes = 2 << 20
	maxErrorResponseBytes      = 4 << 10
)

type (
	Client struct {
		baseURL    *url.URL
		apiKey     string
		httpClient *http.Client
	}

	ClientOption func(*Client)

	ScanReport struct {
		ID                  int64      `json:"id"`
		Platform            string     `json:"platform"`
		ScanTime            time.Time  `json:"scan_time"`
		TargetPath          string     `json:"target_path"`
		TotalScore          int        `json:"total_score"`
		TriggeredRulesCount int        `json:"triggered_rules_count"`
		Risks               []RiskItem `json:"risks"`
	}

	RiskItem struct {
		RuleID         string `json:"rule_id"`
		Title          string `json:"title"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Recommendation string `json:"recommendation"`
	}
)

func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

func NewClient(
	rawBaseURL string,
	apiKey string,
	timeout time.Duration,
	options ...ClientOption,
) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil {
		return nil, fmt.Errorf("cannot parse OpenList scanner URL: %w", err)
	}

	if (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" {
		return nil, fmt.Errorf("OpenList scanner URL must be an absolute HTTP or HTTPS URL")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("OpenList scanner URL must not contain credentials, a query, or a fragment")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("OpenList scanner API key is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("OpenList scanner HTTP timeout must be positive")
	}

	// This CLI adapter intentionally reaches an operator-managed scanner that
	// commonly runs on localhost, a private network, or an in-cluster address.
	// It does not run inside probod, so SSRF protection is intentionally omitted.
	client := &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: httpclient.DefaultClient(),
	}

	for _, option := range options {
		option(client)
	}
	if client.httpClient == nil {
		return nil, fmt.Errorf("OpenList scanner HTTP client is required")
	}

	// The API key is sent in a custom header, so redirects are rejected rather
	// than risking disclosure to a different destination. Operators must provide
	// the scanner's final base URL.
	httpClient := *client.httpClient
	httpClient.Timeout = timeout
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.httpClient = &httpClient

	return client, nil
}

func (c *Client) GetScanReport(ctx context.Context, scanID int64) (*ScanReport, error) {
	if scanID <= 0 {
		return nil, fmt.Errorf("OpenList scan ID must be positive")
	}

	endpoint, err := url.JoinPath(
		c.baseURL.String(),
		"scans",
		url.PathEscape(strconv.FormatInt(scanID, 10)),
	)
	if err != nil {
		return nil, fmt.Errorf("cannot build OpenList scan report URL: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create OpenList scan report request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", version.UserAgent("prb-openlist-adapter"))
	request.Header.Set("X-API-Key", c.apiKey)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch OpenList scan report: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxScanReportResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read OpenList scan report response: %w", err)
	}
	if len(body) > maxScanReportResponseBytes {
		return nil, fmt.Errorf("OpenList scan report response exceeds %d bytes", maxScanReportResponseBytes)
	}

	if response.StatusCode != http.StatusOK {
		errorBody := body
		if len(errorBody) > maxErrorResponseBytes {
			errorBody = append(errorBody[:maxErrorResponseBytes], []byte("...")...)
		}

		return nil, fmt.Errorf(
			"OpenList scanner returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(errorBody)),
		)
	}

	var report ScanReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("cannot decode OpenList scan report: %w", err)
	}
	if report.ID != scanID {
		return nil, fmt.Errorf("OpenList scanner returned report ID %d for requested scan %d", report.ID, scanID)
	}

	return &report, nil
}
