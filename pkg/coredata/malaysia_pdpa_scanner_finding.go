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

package coredata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.gearno.de/kit/pg"
	"go.probo.inc/probo/pkg/crypto/cipher"
	"go.probo.inc/probo/pkg/gid"
	"go.probo.inc/probo/pkg/iam/policy"
)

type MalaysiaPDPAScannerFinding struct {
	ID                gid.GID                            `db:"id"`
	OrganizationID    gid.GID                            `db:"organization_id"`
	FindingID         gid.GID                            `db:"finding_id"`
	ExternalID        string                             `db:"external_id"`
	Source            string                             `db:"source"`
	CheckKey          MalaysiaPDPAScannerCheckKey        `db:"check_key"`
	Severity          MalaysiaPDPAScannerFindingSeverity `db:"severity"`
	Summary           string                             `db:"summary"`
	EncryptedEvidence []byte                             `db:"encrypted_evidence"`
	ObservedAt        time.Time                          `db:"observed_at"`
	RuleVersion       string                             `db:"rule_version"`
	RuleSource        string                             `db:"rule_source"`
	CreatedAt         time.Time                          `db:"created_at"`
	UpdatedAt         time.Time                          `db:"updated_at"`
}

const malaysiaPDPAScannerFindingColumns = `
    id,
    organization_id,
    finding_id,
    external_id,
    source,
    check_key,
    severity,
    summary,
    encrypted_evidence,
    observed_at,
    rule_version,
    rule_source,
    created_at,
    updated_at
`

func (f *MalaysiaPDPAScannerFinding) EncryptEvidence(
	evidence json.RawMessage,
	encryptionKey cipher.EncryptionKey,
) error {
	encryptedEvidence, err := cipher.Encrypt(evidence, encryptionKey)
	if err != nil {
		return fmt.Errorf("cannot encrypt scanner finding evidence: %w", err)
	}

	f.EncryptedEvidence = encryptedEvidence

	return nil
}

func (f *MalaysiaPDPAScannerFinding) DecryptEvidence(
	encryptionKey cipher.EncryptionKey,
) (json.RawMessage, error) {
	if len(f.EncryptedEvidence) == 0 {
		return nil, fmt.Errorf("scanner finding has no encrypted evidence")
	}

	evidence, err := cipher.Decrypt(f.EncryptedEvidence, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt scanner finding evidence: %w", err)
	}

	return json.RawMessage(evidence), nil
}

func (f *MalaysiaPDPAScannerFinding) AuthorizationAttributes(
	ctx context.Context,
	conn pg.Querier,
	resourceIDs []gid.GID,
) (policy.AttributesByID, error) {
	q := `SELECT id, organization_id FROM malaysia_pdpa_scanner_findings WHERE id = ANY(@resource_ids::text[])`

	rows, err := conn.Query(ctx, q, pgx.StrictNamedArgs{"resource_ids": resourceIDs})
	if err != nil {
		return nil, fmt.Errorf("cannot query Malaysia PDPA scanner finding authorization attributes: %w", err)
	}
	defer rows.Close()

	attributes := make(policy.AttributesByID)
	for rows.Next() {
		var id, organizationID gid.GID
		if err := rows.Scan(&id, &organizationID); err != nil {
			return nil, fmt.Errorf("cannot scan Malaysia PDPA scanner finding authorization attributes: %w", err)
		}

		attributes[id] = policy.Attributes{"organization_id": organizationID.String()}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot iterate Malaysia PDPA scanner finding authorization attributes: %w", err)
	}

	return attributes, nil
}

func (f *MalaysiaPDPAScannerFinding) LoadByID(
	ctx context.Context,
	conn pg.Querier,
	scope Scoper,
	id gid.GID,
) error {
	q := `SELECT %s FROM malaysia_pdpa_scanner_findings WHERE %s AND id = @id LIMIT 1;`
	q = fmt.Sprintf(q, malaysiaPDPAScannerFindingColumns, scope.SQLFragment())

	args := pgx.StrictNamedArgs{"id": id}
	maps.Copy(args, scope.SQLArguments())

	rows, err := conn.Query(ctx, q, args)
	if err != nil {
		return fmt.Errorf("cannot query Malaysia PDPA scanner finding: %w", err)
	}

	finding, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[MalaysiaPDPAScannerFinding])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrResourceNotFound
		}

		return fmt.Errorf("cannot collect Malaysia PDPA scanner finding: %w", err)
	}

	*f = finding

	return nil
}

func (f *MalaysiaPDPAScannerFinding) LoadByIdentity(
	ctx context.Context,
	conn pg.Querier,
	scope Scoper,
	organizationID gid.GID,
	source string,
	externalID string,
) error {
	q := `
SELECT %s
FROM malaysia_pdpa_scanner_findings
WHERE
    %s
    AND organization_id = @organization_id
    AND source = @source
    AND external_id = @external_id
LIMIT 1;
`
	q = fmt.Sprintf(q, malaysiaPDPAScannerFindingColumns, scope.SQLFragment())

	args := pgx.StrictNamedArgs{
		"organization_id": organizationID,
		"source":          source,
		"external_id":     externalID,
	}
	maps.Copy(args, scope.SQLArguments())

	rows, err := conn.Query(ctx, q, args)
	if err != nil {
		return fmt.Errorf("cannot query Malaysia PDPA scanner finding by identity: %w", err)
	}

	finding, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[MalaysiaPDPAScannerFinding])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrResourceNotFound
		}

		return fmt.Errorf("cannot collect Malaysia PDPA scanner finding by identity: %w", err)
	}

	*f = finding

	return nil
}

func (f *MalaysiaPDPAScannerFinding) LockIdentity(
	ctx context.Context,
	conn pg.Querier,
	scope Scoper,
) error {
	q := `
SELECT pg_advisory_xact_lock(
    hashtextextended(
        @tenant_id::text || ':' || @organization_id::text || ':' || @source || ':' || @external_id,
        0
    )
);
`

	args := pgx.StrictNamedArgs{
		"tenant_id":       scope.GetTenantID(),
		"organization_id": f.OrganizationID,
		"source":          f.Source,
		"external_id":     f.ExternalID,
	}

	if _, err := conn.Exec(ctx, q, args); err != nil {
		return fmt.Errorf("cannot lock Malaysia PDPA scanner finding identity: %w", err)
	}

	return nil
}

func (f *MalaysiaPDPAScannerFinding) Insert(
	ctx context.Context,
	conn pg.Tx,
	scope Scoper,
) error {
	q := `
INSERT INTO malaysia_pdpa_scanner_findings (
    id,
    tenant_id,
    organization_id,
    finding_id,
    external_id,
    source,
    check_key,
    severity,
    summary,
    encrypted_evidence,
    observed_at,
    rule_version,
    rule_source,
    created_at,
    updated_at
)
VALUES (
    @id,
    @tenant_id,
    @organization_id,
    @finding_id,
    @external_id,
    @source,
    @check_key,
    @severity,
    @summary,
    @encrypted_evidence,
    @observed_at,
    @rule_version,
    @rule_source,
    @created_at,
    @updated_at
);
`

	args := pgx.StrictNamedArgs{
		"id":                 f.ID,
		"tenant_id":          scope.GetTenantID(),
		"organization_id":    f.OrganizationID,
		"finding_id":         f.FindingID,
		"external_id":        f.ExternalID,
		"source":             f.Source,
		"check_key":          f.CheckKey,
		"severity":           f.Severity,
		"summary":            f.Summary,
		"encrypted_evidence": f.EncryptedEvidence,
		"observed_at":        f.ObservedAt,
		"rule_version":       f.RuleVersion,
		"rule_source":        f.RuleSource,
		"created_at":         f.CreatedAt,
		"updated_at":         f.UpdatedAt,
	}

	if _, err := conn.Exec(ctx, q, args); err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok &&
			pgErr.Code == "23505" &&
			pgErr.ConstraintName == "malaysia_pdpa_scanner_findings_identity_key" {
			return ErrResourceAlreadyExists
		}

		return fmt.Errorf("cannot insert Malaysia PDPA scanner finding: %w", err)
	}

	return nil
}

func (f *MalaysiaPDPAScannerFinding) Update(
	ctx context.Context,
	conn pg.Tx,
	scope Scoper,
) error {
	q := `
UPDATE malaysia_pdpa_scanner_findings
SET
    check_key = @check_key,
    severity = @severity,
    summary = @summary,
    encrypted_evidence = @encrypted_evidence,
    observed_at = @observed_at,
    rule_version = @rule_version,
    rule_source = @rule_source,
    updated_at = @updated_at
WHERE
    %s
    AND id = @id;
`
	q = fmt.Sprintf(q, scope.SQLFragment())

	args := pgx.StrictNamedArgs{
		"id":                 f.ID,
		"check_key":          f.CheckKey,
		"severity":           f.Severity,
		"summary":            f.Summary,
		"encrypted_evidence": f.EncryptedEvidence,
		"observed_at":        f.ObservedAt,
		"rule_version":       f.RuleVersion,
		"rule_source":        f.RuleSource,
		"updated_at":         f.UpdatedAt,
	}
	maps.Copy(args, scope.SQLArguments())

	result, err := conn.Exec(ctx, q, args)
	if err != nil {
		return fmt.Errorf("cannot update Malaysia PDPA scanner finding: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrResourceNotFound
	}

	return nil
}

func (f *MalaysiaPDPAScannerFinding) UpdateAssociatedFinding(
	ctx context.Context,
	conn pg.Tx,
	scope Scoper,
	finding *Finding,
) error {
	q := `
UPDATE findings
SET
    kind = @kind,
    description = @description,
    source = @source,
    identified_on = @identified_on,
    priority = @priority,
    updated_at = @updated_at
WHERE
    %s
    AND id = @id
    AND organization_id = @organization_id;
`
	q = fmt.Sprintf(q, scope.SQLFragment())

	args := pgx.StrictNamedArgs{
		"id":              f.FindingID,
		"organization_id": f.OrganizationID,
		"kind":            finding.Kind,
		"description":     finding.Description,
		"source":          finding.Source,
		"identified_on":   finding.IdentifiedOn,
		"priority":        finding.Priority,
		"updated_at":      finding.UpdatedAt,
	}
	maps.Copy(args, scope.SQLArguments())

	result, err := conn.Exec(ctx, q, args)
	if err != nil {
		return fmt.Errorf("cannot update scanner-owned finding fields: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrResourceNotFound
	}

	return nil
}

func (f *MalaysiaPDPAScannerFinding) Delete(
	ctx context.Context,
	conn pg.Tx,
	scope Scoper,
) error {
	q := `DELETE FROM malaysia_pdpa_scanner_findings WHERE %s AND id = @id;`
	q = fmt.Sprintf(q, scope.SQLFragment())

	args := pgx.StrictNamedArgs{"id": f.ID}
	maps.Copy(args, scope.SQLArguments())

	if _, err := conn.Exec(ctx, q, args); err != nil {
		return fmt.Errorf("cannot delete Malaysia PDPA scanner finding: %w", err)
	}

	return nil
}
