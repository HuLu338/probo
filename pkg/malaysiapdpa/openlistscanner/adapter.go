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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/malaysiapdpa"
)

const (
	scannerSource                     = "openlist"
	scannerFindingExternalIDMaxLength = 1000
)

type IngestFinding struct {
	ExternalID  string
	Source      string
	CheckKey    coredata.MalaysiaPDPAScannerCheckKey
	Severity    coredata.MalaysiaPDPAScannerFindingSeverity
	Summary     string
	Evidence    json.RawMessage
	ObservedAt  time.Time
	RuleVersion string
	RuleSource  string
}

type findingEvidence struct {
	ScanReportID   int64  `json:"scan_report_id"`
	Platform       string `json:"platform"`
	TotalScore     int    `json:"total_score"`
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

func BuildIngestFindings(
	report *ScanReport,
	targetID string,
	ruleVersion string,
	ruleSource string,
) ([]IngestFinding, error) {
	if report == nil {
		return nil, fmt.Errorf("OpenList scan report is required")
	}

	if report.ID <= 0 {
		return nil, fmt.Errorf("OpenList scan report ID must be positive")
	}

	if !strings.EqualFold(strings.TrimSpace(report.Platform), scannerSource) {
		return nil, fmt.Errorf("unsupported scanner platform %q", report.Platform)
	}

	if report.ScanTime.IsZero() {
		return nil, fmt.Errorf("OpenList scan time is required")
	}

	targetID = strings.TrimSpace(targetID)
	ruleVersion = strings.TrimSpace(ruleVersion)
	ruleSource = strings.TrimSpace(ruleSource)

	if targetID == "" {
		return nil, fmt.Errorf("stable OpenList target ID is required")
	}

	if strings.ContainsAny(targetID, ":\r\n") {
		return nil, fmt.Errorf("stable OpenList target ID must not contain a colon or newline")
	}

	if ruleVersion == "" {
		return nil, fmt.Errorf("OpenList rule version is required")
	}

	if ruleSource == "" {
		return nil, fmt.Errorf("OpenList rule source is required")
	}

	findings := make([]IngestFinding, 0, len(report.Risks))
	for _, risk := range report.Risks {
		finding, err := buildIngestFinding(report, risk, targetID, ruleVersion, ruleSource)
		if err != nil {
			return nil, err
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func buildIngestFinding(
	report *ScanReport,
	risk RiskItem,
	targetID string,
	ruleVersion string,
	ruleSource string,
) (IngestFinding, error) {
	ruleID := strings.TrimSpace(risk.RuleID)
	if ruleID == "" {
		return IngestFinding{}, fmt.Errorf("OpenList risk rule ID is required")
	}

	if strings.ContainsAny(ruleID, "\r\n") {
		return IngestFinding{}, fmt.Errorf("OpenList risk rule ID must not contain a newline")
	}

	externalID := strings.Join([]string{targetID, ruleID}, ":")
	if len(externalID) > scannerFindingExternalIDMaxLength {
		return IngestFinding{}, fmt.Errorf("OpenList target and rule identity exceeds %d characters", scannerFindingExternalIDMaxLength)
	}

	severity := coredata.MalaysiaPDPAScannerFindingSeverity(strings.ToUpper(strings.TrimSpace(risk.Severity)))
	if !severity.IsValid() {
		return IngestFinding{}, fmt.Errorf("unsupported OpenList risk severity %q for rule %q", risk.Severity, ruleID)
	}

	summary := strings.TrimSpace(risk.Title)
	if summary == "" {
		summary = strings.TrimSpace(risk.Description)
	}

	if summary == "" {
		return IngestFinding{}, fmt.Errorf("OpenList risk summary is required for rule %q", ruleID)
	}

	evidence, err := json.Marshal(
		findingEvidence{
			ScanReportID:   report.ID,
			Platform:       scannerSource,
			TotalScore:     report.TotalScore,
			RuleID:         ruleID,
			Title:          strings.TrimSpace(risk.Title),
			Description:    strings.TrimSpace(risk.Description),
			Recommendation: strings.TrimSpace(risk.Recommendation),
		},
	)
	if err != nil {
		return IngestFinding{}, fmt.Errorf("cannot encode OpenList evidence for rule %q: %w", ruleID, err)
	}

	if len(evidence) > malaysiapdpa.ScannerFindingEvidenceMaxBytes {
		return IngestFinding{}, fmt.Errorf("OpenList evidence for rule %q exceeds %d bytes", ruleID, malaysiapdpa.ScannerFindingEvidenceMaxBytes)
	}

	return IngestFinding{
		ExternalID:  externalID,
		Source:      scannerSource,
		CheckKey:    checkKeyForRule(ruleID),
		Severity:    severity,
		Summary:     summary,
		Evidence:    evidence,
		ObservedAt:  report.ScanTime,
		RuleVersion: ruleVersion,
		RuleSource:  ruleSource,
	}, nil
}

func checkKeyForRule(ruleID string) coredata.MalaysiaPDPAScannerCheckKey {
	switch ruleID {
	case "openlist-tls-skip-verify", "openlist-https-disabled":
		return coredata.MalaysiaPDPAScannerCheckKeyTLS
	case "openlist-token-validity-too-long":
		return coredata.MalaysiaPDPAScannerCheckKeyTokenLifetime
	case "openlist-ftp-enabled", "openlist-sftp-enabled":
		return coredata.MalaysiaPDPAScannerCheckKeyExposedServices
	default:
		return coredata.MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses
	}
}
