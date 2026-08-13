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

package probo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.gearno.de/kit/pg"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/gid"
	"go.probo.inc/probo/pkg/malaysiapdpa"
	"go.probo.inc/probo/pkg/validator"
)

type MalaysiaPDPAScannerFindingService struct {
	svc *Service
}

type (
	IngestMalaysiaPDPAScannerFindingRequest struct {
		OrganizationID gid.GID
		ExternalID     string
		Source         string
		CheckKey       coredata.MalaysiaPDPAScannerCheckKey
		Severity       coredata.MalaysiaPDPAScannerFindingSeverity
		Summary        string
		Evidence       json.RawMessage
		ObservedAt     time.Time
		RuleVersion    string
		RuleSource     string
	}

	MalaysiaPDPAScannerFindingResult struct {
		ScannerFinding *coredata.MalaysiaPDPAScannerFinding
		Finding        *coredata.Finding
		Evidence       json.RawMessage
		Created        bool
	}
)

func (r *IngestMalaysiaPDPAScannerFindingRequest) Validate() error {
	v := validator.New()

	v.Check(r.OrganizationID, "organization_id", validator.Required(), validator.GID(coredata.OrganizationEntityType))
	v.Check(r.ExternalID, "external_id", validator.Required(), validator.SafeTextNoNewLine(TitleMaxLength))
	v.Check(r.Source, "source", validator.Required(), validator.SafeTextNoNewLine(TitleMaxLength))
	v.Check(r.CheckKey, "check_key", validator.Required(), validator.OneOfSlice(coredata.MalaysiaPDPAScannerCheckKeys()))
	v.Check(r.Severity, "severity", validator.Required(), validator.OneOfSlice(coredata.MalaysiaPDPAScannerFindingSeverities()))
	v.Check(r.Summary, "summary", validator.Required(), validator.SafeText(ContentMaxLength))
	v.Check(r.RuleVersion, "rule_version", validator.Required(), validator.SafeTextNoNewLine(TitleMaxLength))
	v.Check(r.RuleSource, "rule_source", validator.Required(), validator.SafeTextNoNewLine(ContentMaxLength))

	if err := v.Error(); err != nil {
		return err
	}

	_, err := malaysiapdpa.AssessScannerFinding(r.domainInput())
	if err == nil {
		return nil
	}

	field := "evidence"

	switch {
	case errors.Is(err, malaysiapdpa.ErrScannerFindingExternalIDRequired):
		field = "external_id"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingSourceRequired):
		field = "source"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingCheckKeyInvalid):
		field = "check_key"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingSeverityInvalid):
		field = "severity"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingSummaryRequired):
		field = "summary"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingObservedAtRequired):
		field = "observed_at"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingRuleVersionRequired):
		field = "rule_version"
	case errors.Is(err, malaysiapdpa.ErrScannerFindingRuleSourceRequired):
		field = "rule_source"
	}

	v.Check(nil, field, func(any) *validator.ValidationError {
		return &validator.ValidationError{
			Code:    validator.ErrorCodeCustom,
			Message: err.Error(),
		}
	})

	return v.Error()
}

func (r *IngestMalaysiaPDPAScannerFindingRequest) domainInput() malaysiapdpa.ScannerFindingInput {
	return malaysiapdpa.ScannerFindingInput{
		ExternalID:  r.ExternalID,
		Source:      r.Source,
		CheckKey:    r.CheckKey,
		Severity:    r.Severity,
		Summary:     r.Summary,
		Evidence:    r.Evidence,
		ObservedAt:  r.ObservedAt,
		RuleVersion: r.RuleVersion,
		RuleSource:  r.RuleSource,
	}
}

func (s *MalaysiaPDPAScannerFindingService) Get(
	ctx context.Context,
	scope coredata.Scoper,
	id gid.GID,
) (*MalaysiaPDPAScannerFindingResult, error) {
	return s.get(ctx, scope, func(ctx context.Context, conn pg.Querier, scannerFinding *coredata.MalaysiaPDPAScannerFinding) error {
		return scannerFinding.LoadByID(ctx, conn, scope, id)
	})
}

func (s *MalaysiaPDPAScannerFindingService) GetByFindingID(
	ctx context.Context,
	scope coredata.Scoper,
	findingID gid.GID,
) (*MalaysiaPDPAScannerFindingResult, error) {
	return s.get(ctx, scope, func(ctx context.Context, conn pg.Querier, scannerFinding *coredata.MalaysiaPDPAScannerFinding) error {
		return scannerFinding.LoadByFindingID(ctx, conn, scope, findingID)
	})
}

func (s *MalaysiaPDPAScannerFindingService) get(
	ctx context.Context,
	scope coredata.Scoper,
	load func(context.Context, pg.Querier, *coredata.MalaysiaPDPAScannerFinding) error,
) (*MalaysiaPDPAScannerFindingResult, error) {
	result := &MalaysiaPDPAScannerFindingResult{
		ScannerFinding: &coredata.MalaysiaPDPAScannerFinding{},
		Finding:        &coredata.Finding{},
	}

	err := s.svc.pg.WithConn(ctx, func(ctx context.Context, conn pg.Querier) error {
		if err := load(ctx, conn, result.ScannerFinding); err != nil {
			return fmt.Errorf("cannot load Malaysia PDPA scanner finding: %w", err)
		}

		if err := result.Finding.LoadByID(ctx, conn, scope, result.ScannerFinding.FindingID); err != nil {
			return fmt.Errorf("cannot load associated finding: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	evidence, err := result.ScannerFinding.DecryptEvidence(s.svc.encryptionKey)
	if err != nil {
		return nil, err
	}

	result.Evidence = evidence

	return result, nil
}

func (s *MalaysiaPDPAScannerFindingService) Ingest(
	ctx context.Context,
	scope coredata.Scoper,
	req *IngestMalaysiaPDPAScannerFindingRequest,
) (*MalaysiaPDPAScannerFindingResult, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	assessment, err := malaysiapdpa.AssessScannerFinding(req.domainInput())
	if err != nil {
		return nil, fmt.Errorf("cannot assess scanner finding: %w", err)
	}

	now := time.Now()
	source := strings.TrimSpace(req.Source)
	summary := strings.TrimSpace(req.Summary)
	observedAt := req.ObservedAt

	scannerFinding := &coredata.MalaysiaPDPAScannerFinding{
		ID:             gid.New(scope.GetTenantID(), coredata.MalaysiaPDPAScannerFindingEntityType),
		OrganizationID: req.OrganizationID,
		FindingID:      gid.New(scope.GetTenantID(), coredata.FindingEntityType),
		ExternalID:     strings.TrimSpace(req.ExternalID),
		Source:         source,
		CheckKey:       req.CheckKey,
		Severity:       req.Severity,
		Summary:        summary,
		ObservedAt:     observedAt,
		RuleVersion:    strings.TrimSpace(req.RuleVersion),
		RuleSource:     strings.TrimSpace(req.RuleSource),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := scannerFinding.EncryptEvidence(req.Evidence, s.svc.encryptionKey); err != nil {
		return nil, err
	}

	finding := &coredata.Finding{
		ID:             scannerFinding.FindingID,
		OrganizationID: req.OrganizationID,
		Kind:           assessment.Kind,
		Description:    &summary,
		Source:         &source,
		IdentifiedOn:   &observedAt,
		Status:         coredata.FindingStatusOpen,
		Priority:       assessment.Priority,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	created := false

	err = s.svc.pg.WithTx(ctx, func(ctx context.Context, tx pg.Tx) error {
		organization := &coredata.Organization{}
		if err := organization.LoadByID(ctx, tx, scope, req.OrganizationID); err != nil {
			return fmt.Errorf("cannot load organization: %w", err)
		}

		if err := scannerFinding.LockIdentity(ctx, tx, scope); err != nil {
			return err
		}

		existing := &coredata.MalaysiaPDPAScannerFinding{}

		err := existing.LoadByIdentity(
			ctx,
			tx,
			scope,
			req.OrganizationID,
			scannerFinding.Source,
			scannerFinding.ExternalID,
		)
		if errors.Is(err, coredata.ErrResourceNotFound) {
			if err := finding.Insert(ctx, tx, scope); err != nil {
				return fmt.Errorf("cannot create associated finding: %w", err)
			}

			if err := scannerFinding.Insert(ctx, tx, scope); err != nil {
				return fmt.Errorf("cannot create Malaysia PDPA scanner finding: %w", err)
			}

			created = true

			return nil
		}

		if err != nil {
			return fmt.Errorf("cannot load existing Malaysia PDPA scanner finding: %w", err)
		}

		scannerFinding.ID = existing.ID
		scannerFinding.FindingID = existing.FindingID
		scannerFinding.CreatedAt = existing.CreatedAt

		finding = &coredata.Finding{}
		if err := finding.LoadByID(ctx, tx, scope, existing.FindingID); err != nil {
			return fmt.Errorf("cannot load associated finding: %w", err)
		}

		if finding.OrganizationID != req.OrganizationID {
			return fmt.Errorf("associated finding belongs to another organization")
		}

		finding.Kind = assessment.Kind
		finding.Description = &summary
		finding.Source = &source
		finding.IdentifiedOn = &observedAt
		finding.Priority = assessment.Priority
		finding.UpdatedAt = now

		if err := scannerFinding.UpdateAssociatedFinding(ctx, tx, scope, finding); err != nil {
			return fmt.Errorf("cannot update associated finding: %w", err)
		}

		if err := scannerFinding.Update(ctx, tx, scope); err != nil {
			return fmt.Errorf("cannot update Malaysia PDPA scanner finding: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &MalaysiaPDPAScannerFindingResult{
		ScannerFinding: scannerFinding,
		Finding:        finding,
		Evidence:       append(json.RawMessage(nil), req.Evidence...),
		Created:        created,
	}, nil
}
