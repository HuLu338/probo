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

package malaysiapdpa_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/malaysiapdpa"
)

func TestAssessScannerFinding_SeverityMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		severity         malaysiapdpa.ScannerFindingSeverity
		expectedKind     coredata.FindingKind
		expectedPriority coredata.FindingPriority
	}{
		{
			name:             "low severity becomes a low priority observation",
			severity:         malaysiapdpa.ScannerFindingSeverityLow,
			expectedKind:     coredata.FindingKindObservation,
			expectedPriority: coredata.FindingPriorityLow,
		},
		{
			name:             "medium severity becomes a medium priority minor nonconformity",
			severity:         malaysiapdpa.ScannerFindingSeverityMedium,
			expectedKind:     coredata.FindingKindMinorNonconformity,
			expectedPriority: coredata.FindingPriorityMedium,
		},
		{
			name:             "high severity becomes a high priority major nonconformity",
			severity:         malaysiapdpa.ScannerFindingSeverityHigh,
			expectedKind:     coredata.FindingKindMajorNonconformity,
			expectedPriority: coredata.FindingPriorityHigh,
		},
		{
			name:             "critical severity becomes a high priority major nonconformity",
			severity:         malaysiapdpa.ScannerFindingSeverityCritical,
			expectedKind:     coredata.FindingKindMajorNonconformity,
			expectedPriority: coredata.FindingPriorityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				input := validScannerFindingInput()
				input.Severity = tt.severity

				assessment, err := malaysiapdpa.AssessScannerFinding(input)

				require.NoError(t, err)
				assert.Equal(t, tt.expectedKind, assessment.Kind)
				assert.Equal(t, tt.expectedPriority, assessment.Priority)
			},
		)
	}
}

func TestAssessScannerFinding_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		modify        func(*malaysiapdpa.ScannerFindingInput)
		expectedError error
	}{
		{
			name: "external ID is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.ExternalID = " "
			},
			expectedError: malaysiapdpa.ErrScannerFindingExternalIDRequired,
		},
		{
			name: "source is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Source = " "
			},
			expectedError: malaysiapdpa.ErrScannerFindingSourceRequired,
		},
		{
			name: "check key must be supported",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.CheckKey = malaysiapdpa.ScannerCheckKey("UNSUPPORTED")
			},
			expectedError: malaysiapdpa.ErrScannerFindingCheckKeyInvalid,
		},
		{
			name: "severity must be supported",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Severity = malaysiapdpa.ScannerFindingSeverity("INFO")
			},
			expectedError: malaysiapdpa.ErrScannerFindingSeverityInvalid,
		},
		{
			name: "summary is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Summary = "\t"
			},
			expectedError: malaysiapdpa.ErrScannerFindingSummaryRequired,
		},
		{
			name: "evidence is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Evidence = nil
			},
			expectedError: malaysiapdpa.ErrScannerFindingEvidenceRequired,
		},
		{
			name: "evidence must be valid JSON",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Evidence = json.RawMessage(`{"port":`)
			},
			expectedError: malaysiapdpa.ErrScannerFindingEvidenceInvalid,
		},
		{
			name: "evidence must stay within the ingestion limit",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Evidence = make(json.RawMessage, malaysiapdpa.ScannerFindingEvidenceMaxBytes+1)
			},
			expectedError: malaysiapdpa.ErrScannerFindingEvidenceTooLarge,
		},
		{
			name: "evidence must be an object",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Evidence = json.RawMessage(`[443]`)
			},
			expectedError: malaysiapdpa.ErrScannerFindingEvidenceInvalid,
		},
		{
			name: "evidence object must not be empty",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.Evidence = json.RawMessage(`{}`)
			},
			expectedError: malaysiapdpa.ErrScannerFindingEvidenceInvalid,
		},
		{
			name: "observation time is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.ObservedAt = time.Time{}
			},
			expectedError: malaysiapdpa.ErrScannerFindingObservedAtRequired,
		},
		{
			name: "rule version is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.RuleVersion = ""
			},
			expectedError: malaysiapdpa.ErrScannerFindingRuleVersionRequired,
		},
		{
			name: "rule source is required",
			modify: func(input *malaysiapdpa.ScannerFindingInput) {
				input.RuleSource = " "
			},
			expectedError: malaysiapdpa.ErrScannerFindingRuleSourceRequired,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				input := validScannerFindingInput()
				tt.modify(&input)

				_, err := malaysiapdpa.AssessScannerFinding(input)

				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			},
		)
	}
}

func TestScannerCheckKeys_MVPChecks(t *testing.T) {
	t.Parallel()

	expected := []malaysiapdpa.ScannerCheckKey{
		malaysiapdpa.ScannerCheckKeyMFA,
		malaysiapdpa.ScannerCheckKeyExposedServices,
		malaysiapdpa.ScannerCheckKeyTLS,
		malaysiapdpa.ScannerCheckKeyTokenLifetime,
		malaysiapdpa.ScannerCheckKeyBackupEvidence,
		malaysiapdpa.ScannerCheckKeyPrivilegedAccounts,
		malaysiapdpa.ScannerCheckKeyConfigurationWeaknesses,
	}

	assert.Equal(t, expected, malaysiapdpa.ScannerCheckKeys())
	for _, checkKey := range expected {
		assert.True(t, checkKey.IsValid())
	}
}

func validScannerFindingInput() malaysiapdpa.ScannerFindingInput {
	return malaysiapdpa.ScannerFindingInput{
		ExternalID:  "scanner-finding-001",
		Source:      "openlist",
		CheckKey:    malaysiapdpa.ScannerCheckKeyExposedServices,
		Severity:    malaysiapdpa.ScannerFindingSeverityHigh,
		Summary:     "Administrative service is publicly exposed",
		Evidence:    json.RawMessage(`{"port":8443,"transport":"tcp"}`),
		ObservedAt:  time.Date(2026, time.August, 12, 3, 0, 0, 0, time.UTC),
		RuleVersion: "scanner-rules-2026.08",
		RuleSource:  "https://scanner.example/rules/exposed-services",
	}
}
