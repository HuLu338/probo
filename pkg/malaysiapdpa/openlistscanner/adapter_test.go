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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/malaysiapdpa/openlistscanner"
)

func TestBuildIngestFindings_MapsOpenListRules(t *testing.T) {
	t.Parallel()

	observedAt := time.Date(2026, time.August, 12, 4, 10, 0, 0, time.UTC)
	report := &openlistscanner.ScanReport{
		ID:         42,
		Platform:   "openlist",
		ScanTime:   observedAt,
		TargetPath: "/etc/openlist/config.json",
		TotalScore: 55,
		Risks: []openlistscanner.RiskItem{
			{RuleID: "openlist-tls-skip-verify", Title: "TLS verification skipped", Severity: "high"},
			{RuleID: "openlist-https-disabled", Title: "HTTPS disabled", Severity: "high"},
			{RuleID: "openlist-token-validity-too-long", Title: "Long token validity", Severity: "medium"},
			{RuleID: "openlist-ftp-enabled", Title: "FTP enabled", Severity: "medium"},
			{RuleID: "openlist-sftp-enabled", Title: "SFTP enabled", Severity: "low"},
			{RuleID: "openlist-jwt-secret-weak", Title: "Weak JWT secret", Severity: "critical"},
			{
				RuleID:         "openlist-logging-disabled",
				Title:          "Logging disabled",
				Severity:       "low",
				Description:    "Application logging is disabled.",
				Recommendation: "Enable security logging.",
			},
		},
	}

	findings, err := openlistscanner.BuildIngestFindings(
		report,
		"customer-a-openlist",
		"2026.08",
		"https://scanner.example/rules/openlist",
	)
	require.NoError(t, err)
	require.Len(t, findings, 7)

	expectedCheckKeys := []coredata.MalaysiaPDPAScannerCheckKey{
		coredata.MalaysiaPDPAScannerCheckKeyTLS,
		coredata.MalaysiaPDPAScannerCheckKeyTLS,
		coredata.MalaysiaPDPAScannerCheckKeyTokenLifetime,
		coredata.MalaysiaPDPAScannerCheckKeyExposedServices,
		coredata.MalaysiaPDPAScannerCheckKeyExposedServices,
		coredata.MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses,
		coredata.MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses,
	}
	for i, finding := range findings {
		assert.Equal(t, expectedCheckKeys[i], finding.CheckKey)
		assert.Equal(t, "openlist", finding.Source)
		assert.Equal(t, observedAt, finding.ObservedAt)
		assert.Contains(t, finding.ExternalID, "customer-a-openlist:")
		assert.NotContains(t, string(finding.Evidence), report.TargetPath)
	}

	assert.Equal(t, coredata.MalaysiaPDPAScannerFindingSeverityCritical, findings[5].Severity)
	assert.JSONEq(
		t,
		`{"scan_report_id":42,"platform":"openlist","total_score":55,"rule_id":"openlist-logging-disabled","title":"Logging disabled","description":"Application logging is disabled.","recommendation":"Enable security logging."}`,
		string(findings[6].Evidence),
	)
}

func TestBuildIngestFindings_ValidatesScannerContract(t *testing.T) {
	t.Parallel()

	validReport := func() *openlistscanner.ScanReport {
		return &openlistscanner.ScanReport{
			ID:       42,
			Platform: "openlist",
			ScanTime: time.Date(2026, time.August, 12, 4, 10, 0, 0, time.UTC),
			Risks: []openlistscanner.RiskItem{
				{RuleID: "openlist-https-disabled", Title: "HTTPS disabled", Severity: "high"},
			},
		}
	}

	tests := []struct {
		name          string
		modify        func(*openlistscanner.ScanReport)
		targetID      string
		ruleVersion   string
		errorContains string
	}{
		{name: "missing target ID", targetID: "", ruleVersion: "2026.08", errorContains: "target ID"},
		{name: "missing rule version", targetID: "target", ruleVersion: "", errorContains: "rule version"},
		{
			name: "unsupported platform",
			modify: func(report *openlistscanner.ScanReport) {
				report.Platform = "other"
			},
			targetID:      "target",
			ruleVersion:   "2026.08",
			errorContains: "unsupported scanner platform",
		},
		{
			name: "unsupported severity",
			modify: func(report *openlistscanner.ScanReport) {
				report.Risks[0].Severity = "urgent"
			},
			targetID:      "target",
			ruleVersion:   "2026.08",
			errorContains: "unsupported OpenList risk severity",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				report := validReport()
				if tt.modify != nil {
					tt.modify(report)
				}

				_, err := openlistscanner.BuildIngestFindings(
					report,
					tt.targetID,
					tt.ruleVersion,
					"https://scanner.example.test/rules",
				)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			},
		)
	}
}
