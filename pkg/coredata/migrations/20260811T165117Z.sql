-- Copyright (c) 2026 Probo Inc <hello@probo.com>.
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.

CREATE TYPE malaysia_pdpa_scanner_check_key AS ENUM (
    'MFA',
    'EXPOSED_SERVICES',
    'TLS',
    'TOKEN_LIFETIME',
    'BACKUP_EVIDENCE',
    'PRIVILEGED_ACCOUNTS',
    'CONFIGURATION_WEAKNESSES'
);

CREATE TYPE malaysia_pdpa_scanner_finding_severity AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TABLE malaysia_pdpa_scanner_findings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    source TEXT NOT NULL,
    check_key malaysia_pdpa_scanner_check_key NOT NULL,
    severity malaysia_pdpa_scanner_finding_severity NOT NULL,
    summary TEXT NOT NULL,
    encrypted_evidence BYTEA NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    rule_version TEXT NOT NULL,
    rule_source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT malaysia_pdpa_scanner_findings_identity_key
        UNIQUE (tenant_id, organization_id, source, external_id),
    CONSTRAINT malaysia_pdpa_scanner_findings_finding_id_key
        UNIQUE (finding_id)
);
