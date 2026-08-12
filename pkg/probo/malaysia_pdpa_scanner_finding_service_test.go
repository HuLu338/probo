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
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/gid"
	"go.probo.inc/probo/pkg/malaysiapdpa"
	"go.probo.inc/probo/pkg/validator"
)

func TestIngestMalaysiaPDPAScannerFindingRequestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		modify        func(*IngestMalaysiaPDPAScannerFindingRequest)
		expectedField string
	}{
		{
			name: "accepts a valid request",
		},
		{
			name: "requires an organization entity ID",
			modify: func(req *IngestMalaysiaPDPAScannerFindingRequest) {
				req.OrganizationID = gid.New(gid.NewTenantID(), coredata.FindingEntityType)
			},
			expectedField: "organization_id",
		},
		{
			name: "requires a stable source",
			modify: func(req *IngestMalaysiaPDPAScannerFindingRequest) {
				req.Source = " "
			},
			expectedField: "source",
		},
		{
			name: "rejects an unsupported check key",
			modify: func(req *IngestMalaysiaPDPAScannerFindingRequest) {
				req.CheckKey = coredata.MalaysiaPDPAScannerCheckKey("UNSUPPORTED")
			},
			expectedField: "check_key",
		},
		{
			name: "rejects invalid JSON evidence",
			modify: func(req *IngestMalaysiaPDPAScannerFindingRequest) {
				req.Evidence = json.RawMessage(`{"port":`)
			},
			expectedField: "evidence",
		},
		{
			name: "rejects evidence above the ingestion limit",
			modify: func(req *IngestMalaysiaPDPAScannerFindingRequest) {
				req.Evidence = make(json.RawMessage, malaysiapdpa.ScannerFindingEvidenceMaxBytes+1)
			},
			expectedField: "evidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := validIngestMalaysiaPDPAScannerFindingRequest()
			if tt.modify != nil {
				tt.modify(&req)
			}

			err := req.Validate()
			if tt.expectedField == "" {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			validationErrors, ok := err.(validator.ValidationErrors)
			require.True(t, ok)
			assert.NotEmpty(t, validationErrors.ByField(tt.expectedField))
		})
	}
}

func validIngestMalaysiaPDPAScannerFindingRequest() IngestMalaysiaPDPAScannerFindingRequest {
	tenantID := gid.NewTenantID()

	return IngestMalaysiaPDPAScannerFindingRequest{
		OrganizationID: gid.New(tenantID, coredata.OrganizationEntityType),
		ExternalID:     "scanner-finding-001",
		Source:         "openlist",
		CheckKey:       coredata.MalaysiaPDPAScannerCheckKeyExposedServices,
		Severity:       coredata.MalaysiaPDPAScannerFindingSeverityHigh,
		Summary:        "Administrative service is publicly exposed",
		Evidence:       json.RawMessage(`{"port":8443,"transport":"tcp"}`),
		ObservedAt:     time.Date(2026, time.August, 12, 3, 0, 0, 0, time.UTC),
		RuleVersion:    "scanner-rules-2026.08",
		RuleSource:     "https://scanner.example/rules/exposed-services",
	}
}
