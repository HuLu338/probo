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

package malaysiapdpa

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"go.probo.inc/probo/pkg/coredata"
)

type (
	ScannerCheckKey = coredata.MalaysiaPDPAScannerCheckKey

	ScannerFindingSeverity = coredata.MalaysiaPDPAScannerFindingSeverity

	ScannerFindingInput struct {
		ExternalID  string
		Source      string
		CheckKey    ScannerCheckKey
		Severity    ScannerFindingSeverity
		Summary     string
		Evidence    json.RawMessage
		ObservedAt  time.Time
		RuleVersion string
		RuleSource  string
	}

	ScannerFindingAssessment struct {
		Kind     coredata.FindingKind
		Priority coredata.FindingPriority
	}
)

const (
	ScannerCheckKeyMFA                     = coredata.MalaysiaPDPAScannerCheckKeyMFA
	ScannerCheckKeyExposedServices         = coredata.MalaysiaPDPAScannerCheckKeyExposedServices
	ScannerCheckKeyTLS                     = coredata.MalaysiaPDPAScannerCheckKeyTLS
	ScannerCheckKeyTokenLifetime           = coredata.MalaysiaPDPAScannerCheckKeyTokenLifetime
	ScannerCheckKeyBackupEvidence          = coredata.MalaysiaPDPAScannerCheckKeyBackupEvidence
	ScannerCheckKeyPrivilegedAccounts      = coredata.MalaysiaPDPAScannerCheckKeyPrivilegedAccounts
	ScannerCheckKeyConfigurationWeaknesses = coredata.MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses

	ScannerFindingSeverityLow      = coredata.MalaysiaPDPAScannerFindingSeverityLow
	ScannerFindingSeverityMedium   = coredata.MalaysiaPDPAScannerFindingSeverityMedium
	ScannerFindingSeverityHigh     = coredata.MalaysiaPDPAScannerFindingSeverityHigh
	ScannerFindingSeverityCritical = coredata.MalaysiaPDPAScannerFindingSeverityCritical

	ScannerFindingEvidenceMaxBytes = 1 << 20
)

var (
	ErrScannerFindingExternalIDRequired  = errors.New("scanner finding external ID is required")
	ErrScannerFindingSourceRequired      = errors.New("scanner finding source is required")
	ErrScannerFindingCheckKeyInvalid     = errors.New("scanner finding check key is invalid")
	ErrScannerFindingSeverityInvalid     = errors.New("scanner finding severity is invalid")
	ErrScannerFindingSummaryRequired     = errors.New("scanner finding summary is required")
	ErrScannerFindingEvidenceRequired    = errors.New("scanner finding evidence is required")
	ErrScannerFindingEvidenceTooLarge    = errors.New("scanner finding evidence is too large")
	ErrScannerFindingEvidenceInvalid     = errors.New("scanner finding evidence must be a JSON object")
	ErrScannerFindingObservedAtRequired  = errors.New("scanner finding observation time is required")
	ErrScannerFindingRuleVersionRequired = errors.New("scanner finding rule version is required")
	ErrScannerFindingRuleSourceRequired  = errors.New("scanner finding rule source is required")
)

func ScannerCheckKeys() []ScannerCheckKey {
	return coredata.MalaysiaPDPAScannerCheckKeys()
}

func ScannerFindingSeverities() []ScannerFindingSeverity {
	return coredata.MalaysiaPDPAScannerFindingSeverities()
}

func AssessScannerFinding(input ScannerFindingInput) (ScannerFindingAssessment, error) {
	if strings.TrimSpace(input.ExternalID) == "" {
		return ScannerFindingAssessment{}, ErrScannerFindingExternalIDRequired
	}

	if strings.TrimSpace(input.Source) == "" {
		return ScannerFindingAssessment{}, ErrScannerFindingSourceRequired
	}

	if !input.CheckKey.IsValid() {
		return ScannerFindingAssessment{}, ErrScannerFindingCheckKeyInvalid
	}

	if !input.Severity.IsValid() {
		return ScannerFindingAssessment{}, ErrScannerFindingSeverityInvalid
	}

	if strings.TrimSpace(input.Summary) == "" {
		return ScannerFindingAssessment{}, ErrScannerFindingSummaryRequired
	}

	if len(input.Evidence) == 0 {
		return ScannerFindingAssessment{}, ErrScannerFindingEvidenceRequired
	}

	if len(input.Evidence) > ScannerFindingEvidenceMaxBytes {
		return ScannerFindingAssessment{}, ErrScannerFindingEvidenceTooLarge
	}

	var evidence map[string]any
	if err := json.Unmarshal(input.Evidence, &evidence); err != nil || len(evidence) == 0 {
		return ScannerFindingAssessment{}, ErrScannerFindingEvidenceInvalid
	}

	if input.ObservedAt.IsZero() {
		return ScannerFindingAssessment{}, ErrScannerFindingObservedAtRequired
	}

	if strings.TrimSpace(input.RuleVersion) == "" {
		return ScannerFindingAssessment{}, ErrScannerFindingRuleVersionRequired
	}

	if strings.TrimSpace(input.RuleSource) == "" {
		return ScannerFindingAssessment{}, ErrScannerFindingRuleSourceRequired
	}

	assessment := ScannerFindingAssessment{
		Kind:     coredata.FindingKindObservation,
		Priority: coredata.FindingPriorityLow,
	}

	switch input.Severity {
	case ScannerFindingSeverityCritical, ScannerFindingSeverityHigh:
		assessment.Kind = coredata.FindingKindMajorNonconformity
		assessment.Priority = coredata.FindingPriorityHigh
	case ScannerFindingSeverityMedium:
		assessment.Kind = coredata.FindingKindMinorNonconformity
		assessment.Priority = coredata.FindingPriorityMedium
	}

	return assessment, nil
}
