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

package console_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/e2e/internal/testutil"
)

const ingestMalaysiaPDPAScannerFindingMutation = `
	mutation IngestMalaysiaPDPAScannerFinding($input: IngestMalaysiaPDPAScannerFindingInput!) {
		ingestMalaysiaPDPAScannerFinding(input: $input) {
			created
			scannerFinding {
				id organizationId externalId source checkKey severity summary evidence
				observedAt ruleVersion ruleSource createdAt updatedAt
				finding { id referenceId kind priority status rootCause }
			}
			finding { id referenceId kind priority status }
		}
	}
`

type malaysiaPDPAScannerFindingResult struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	ExternalID     string `json:"externalId"`
	Source         string `json:"source"`
	CheckKey       string `json:"checkKey"`
	Severity       string `json:"severity"`
	Summary        string `json:"summary"`
	Evidence       string `json:"evidence"`
	RuleVersion    string `json:"ruleVersion"`
	Finding        struct {
		ID          string  `json:"id"`
		ReferenceID string  `json:"referenceId"`
		Kind        string  `json:"kind"`
		Priority    string  `json:"priority"`
		Status      string  `json:"status"`
		RootCause   *string `json:"rootCause"`
	} `json:"finding"`
}

type ingestMalaysiaPDPAScannerFindingResult struct {
	Created        bool                             `json:"created"`
	ScannerFinding malaysiaPDPAScannerFindingResult `json:"scannerFinding"`
}

func TestMalaysiaPDPAScannerFinding_IdempotentIngestionAndRBAC(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	viewer := testutil.NewClientInOrg(t, testutil.RoleViewer, owner)
	otherOwner := testutil.NewClient(t, testutil.RoleOwner)
	input := malaysiaPDPAScannerFindingInput(owner)

	created := ingestMalaysiaPDPAScannerFinding(t, owner, input)
	assert.True(t, created.Created)
	assert.Equal(t, "HIGH", created.ScannerFinding.Severity)
	assert.Equal(t, "MAJOR_NONCONFORMITY", created.ScannerFinding.Finding.Kind)
	assert.Equal(t, "HIGH", created.ScannerFinding.Finding.Priority)
	assert.JSONEq(t, input["evidence"].(string), created.ScannerFinding.Evidence)

	var updateFindingResult struct {
		Update struct {
			Finding struct {
				ID string `json:"id"`
			} `json:"finding"`
		} `json:"updateFinding"`
	}

	err := owner.Execute(
		`mutation($input: UpdateFindingInput!) { updateFinding(input: $input) { finding { id } } }`,
		map[string]any{"input": map[string]any{
			"id":        created.ScannerFinding.Finding.ID,
			"status":    "IN_PROGRESS",
			"rootCause": "The service was published by a legacy ingress rule",
		}},
		&updateFindingResult,
	)
	require.NoError(t, err)

	input["severity"] = "LOW"
	input["summary"] = "Service exposure was reduced to an informational observation"
	input["evidence"] = `{"port":443,"transport":"tcp"}`
	updated := ingestMalaysiaPDPAScannerFinding(t, owner, input)
	assert.False(t, updated.Created)
	assert.Equal(t, created.ScannerFinding.ID, updated.ScannerFinding.ID)
	assert.Equal(t, created.ScannerFinding.Finding.ID, updated.ScannerFinding.Finding.ID)
	assert.Equal(t, created.ScannerFinding.Finding.ReferenceID, updated.ScannerFinding.Finding.ReferenceID)
	assert.Equal(t, "OBSERVATION", updated.ScannerFinding.Finding.Kind)
	assert.Equal(t, "LOW", updated.ScannerFinding.Finding.Priority)
	assert.Equal(t, "IN_PROGRESS", updated.ScannerFinding.Finding.Status)
	require.NotNil(t, updated.ScannerFinding.Finding.RootCause)
	assert.Equal(t, "The service was published by a legacy ingress rule", *updated.ScannerFinding.Finding.RootCause)
	assert.JSONEq(t, input["evidence"].(string), updated.ScannerFinding.Evidence)

	var viewerNode struct {
		Node *malaysiaPDPAScannerFindingResult `json:"node"`
	}

	err = viewer.Execute(`query($id: ID!) { node(id: $id) { ... on MalaysiaPDPAScannerFinding { id evidence finding { id } } } }`, map[string]any{"id": created.ScannerFinding.ID}, &viewerNode)
	require.NoError(t, err)
	require.NotNil(t, viewerNode.Node)
	assert.Equal(t, created.ScannerFinding.ID, viewerNode.Node.ID)
	assert.JSONEq(t, input["evidence"].(string), viewerNode.Node.Evidence)

	var viewerFindingNode struct {
		Node *struct {
			ID             string                            `json:"id"`
			ScannerFinding *malaysiaPDPAScannerFindingResult `json:"malaysiaPDPAScannerFinding"`
		} `json:"node"`
	}

	err = viewer.Execute(
		`query($id: ID!) { node(id: $id) { ... on Finding { id malaysiaPDPAScannerFinding { id source ruleVersion evidence } } } }`,
		map[string]any{"id": created.ScannerFinding.Finding.ID},
		&viewerFindingNode,
	)
	require.NoError(t, err)
	require.NotNil(t, viewerFindingNode.Node)
	require.NotNil(t, viewerFindingNode.Node.ScannerFinding)
	assert.Equal(t, created.ScannerFinding.Finding.ID, viewerFindingNode.Node.ID)
	assert.Equal(t, created.ScannerFinding.ID, viewerFindingNode.Node.ScannerFinding.ID)
	assert.Equal(t, input["source"], viewerFindingNode.Node.ScannerFinding.Source)
	assert.Equal(t, input["ruleVersion"], viewerFindingNode.Node.ScannerFinding.RuleVersion)
	assert.JSONEq(t, input["evidence"].(string), viewerFindingNode.Node.ScannerFinding.Evidence)

	_, err = viewer.Do(ingestMalaysiaPDPAScannerFindingMutation, map[string]any{"input": input})
	testutil.RequireForbiddenError(t, err, "viewer cannot ingest Malaysia PDPA scanner findings")

	var inaccessible struct {
		Node *malaysiaPDPAScannerFindingResult `json:"node"`
	}

	err = otherOwner.Execute(`query($id: ID!) { node(id: $id) { ... on MalaysiaPDPAScannerFinding { id } } }`, map[string]any{"id": created.ScannerFinding.ID}, &inaccessible)
	testutil.AssertNodeNotAccessible(t, err, inaccessible.Node == nil, "Malaysia PDPA scanner finding")

	var inaccessibleFinding struct {
		Node *struct {
			ID string `json:"id"`
		} `json:"node"`
	}

	err = otherOwner.Execute(
		`query($id: ID!) { node(id: $id) { ... on Finding { id malaysiaPDPAScannerFinding { id } } } }`,
		map[string]any{"id": created.ScannerFinding.Finding.ID},
		&inaccessibleFinding,
	)
	testutil.AssertNodeNotAccessible(t, err, inaccessibleFinding.Node == nil, "scanner-associated finding")
}

func ingestMalaysiaPDPAScannerFinding(
	t *testing.T,
	client *testutil.Client,
	input map[string]any,
) ingestMalaysiaPDPAScannerFindingResult {
	t.Helper()

	var result struct {
		Ingest ingestMalaysiaPDPAScannerFindingResult `json:"ingestMalaysiaPDPAScannerFinding"`
	}

	err := client.Execute(
		ingestMalaysiaPDPAScannerFindingMutation,
		map[string]any{"input": input},
		&result,
	)
	require.NoError(t, err)

	return result.Ingest
}

func malaysiaPDPAScannerFindingInput(client *testutil.Client) map[string]any {
	observedAt := time.Date(2026, time.August, 12, 3, 0, 0, 0, time.UTC)
	evidence, _ := json.Marshal(map[string]any{"port": 8443, "transport": "tcp"})

	return map[string]any{
		"organizationId": client.GetOrganizationID().String(),
		"externalId":     "scanner-finding-001",
		"source":         "openlist",
		"checkKey":       "EXPOSED_SERVICES",
		"severity":       "HIGH",
		"summary":        "Administrative service is publicly exposed",
		"evidence":       string(evidence),
		"observedAt":     observedAt.Format(time.RFC3339),
		"ruleVersion":    "scanner-rules-2026.08",
		"ruleSource":     "https://scanner.example/rules/exposed-services",
	}
}
