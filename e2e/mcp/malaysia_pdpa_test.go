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

package mcp_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/e2e/internal/factory"
	"go.probo.inc/probo/e2e/internal/testutil"
)

type mcpMalaysiaPDPAProfile struct {
	DPORequired           bool     `json:"dpo_required"`
	DPORequirementReasons []string `json:"dpo_requirement_reasons"`
	RuleVersion           string   `json:"rule_version"`
	RuleSource            string   `json:"rule_source"`
}

func TestMCP_MalaysiaPDPAProfile_UpdateAndGet(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	mc := testutil.NewMCPClient(t, owner)
	organizationID := owner.GetOrganizationID().String()

	var updateResult struct {
		Profile mcpMalaysiaPDPAProfile `json:"malaysia_pdpa_profile"`
	}
	mc.CallToolInto("updateMalaysiaPDPAProfile", map[string]any{
		"organization_id":               organizationID,
		"total_data_subjects":           20_001,
		"sensitive_data_subjects":       10_000,
		"regular_systematic_monitoring": false,
	}, &updateResult)

	assert.True(t, updateResult.Profile.DPORequired)
	assert.Equal(t, []string{"PERSONAL_DATA_VOLUME"}, updateResult.Profile.DPORequirementReasons)
	assert.Equal(t, "MY-PDPA-DPO-2025-06-01", updateResult.Profile.RuleVersion)
	assert.Equal(t, "https://www.pdp.gov.my/ppdpv1/wp-content/uploads/2025/08/GP_DPO_ENG.pdf", updateResult.Profile.RuleSource)

	var getResult struct {
		Profile mcpMalaysiaPDPAProfile `json:"malaysia_pdpa_profile"`
	}
	mc.CallToolInto("getMalaysiaPDPAProfile", map[string]any{
		"organization_id": organizationID,
	}, &getResult)

	assert.Equal(t, updateResult.Profile, getResult.Profile)
}

func TestMCP_MalaysiaPDPABreach_Lifecycle(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	mc := testutil.NewMCPClient(t, owner)
	organizationID := owner.GetOrganizationID().String()
	awarenessAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)
	commissionerNotifiedAt := awarenessAt.Add(24 * time.Hour)

	type incident struct {
		ID                         string     `json:"id"`
		Title                      string     `json:"title"`
		PhasedInformationDueAt     *time.Time `json:"phased_information_due_at"`
		PhasedInformationOverdue   bool       `json:"phased_information_overdue"`
		CommissionerNotifiedAt     *time.Time `json:"commissioner_notified_at"`
		NotificationRecommendation string     `json:"notification_recommendation"`
		Status                     string     `json:"status"`
	}

	var createResult struct {
		Incident incident `json:"incident"`
	}
	mc.CallToolInto("createMalaysiaPDPABreachIncident", map[string]any{
		"organization_id":                     organizationID,
		"title":                               "MCP phased-information lifecycle",
		"discovered_at":                       awarenessAt.Add(-time.Hour).Format(time.RFC3339),
		"awareness_at":                        awarenessAt.Format(time.RFC3339),
		"affected_data_subjects":              1_001,
		"affected_data_records":               1_001,
		"personal_data_types":                 "Names and email addresses",
		"potential_physical_harm":             false,
		"potential_financial_loss":            false,
		"potential_credit_or_property_damage": false,
		"potential_illegal_use":               false,
		"sensitive_personal_data":             false,
		"potential_identity_fraud":            false,
		"notification_decision":               "COMMISSIONER_ONLY",
		"decision_rationale":                  "Significant scale requires Commissioner notification.",
		"commissioner_notified_at":            commissionerNotifiedAt.Format(time.RFC3339),
		"commissioner_notification_reference": "MCP-DBN-0001",
	}, &createResult)

	require.NotEmpty(t, createResult.Incident.ID)
	require.NotNil(t, createResult.Incident.PhasedInformationDueAt)
	assert.Equal(t, commissionerNotifiedAt.Add(30*24*time.Hour), *createResult.Incident.PhasedInformationDueAt)
	assert.True(t, createResult.Incident.PhasedInformationOverdue)
	assert.Equal(t, "COMMISSIONER_ONLY", createResult.Incident.NotificationRecommendation)

	var getResult struct {
		Incident incident `json:"incident"`
	}
	mc.CallToolInto("getMalaysiaPDPABreachIncident", map[string]any{"id": createResult.Incident.ID}, &getResult)
	assert.Equal(t, createResult.Incident.ID, getResult.Incident.ID)
	assert.True(t, getResult.Incident.PhasedInformationOverdue)

	var listResult struct {
		Incidents []incident `json:"incidents"`
	}
	mc.CallToolInto("listMalaysiaPDPABreachIncidents", map[string]any{"organization_id": organizationID}, &listResult)
	assert.NotEmpty(t, listResult.Incidents)

	var updateResult struct {
		Incident incident `json:"incident"`
	}
	mc.CallToolInto("updateMalaysiaPDPABreachIncident", map[string]any{
		"id":    createResult.Incident.ID,
		"title": "Updated MCP phased-information lifecycle",
	}, &updateResult)
	assert.Equal(t, "Updated MCP phased-information lifecycle", updateResult.Incident.Title)

	var transitionResult struct {
		Incident incident `json:"incident"`
		History  struct {
			ToStatus string `json:"to_status"`
		} `json:"history"`
	}
	mc.CallToolInto("transitionMalaysiaPDPABreachStatus", map[string]any{
		"id":        createResult.Incident.ID,
		"to_status": "ASSESSING",
		"reason":    "MCP lifecycle coverage",
	}, &transitionResult)
	assert.Equal(t, "ASSESSING", transitionResult.Incident.Status)
	assert.Equal(t, "ASSESSING", transitionResult.History.ToStatus)

	var historyResult struct {
		History []struct {
			ToStatus string `json:"to_status"`
		} `json:"history"`
	}
	mc.CallToolInto("listMalaysiaPDPABreachStatusHistory", map[string]any{
		"incident_id": createResult.Incident.ID,
	}, &historyResult)
	require.Len(t, historyResult.History, 2)
	assert.ElementsMatch(t, []string{"OPEN", "ASSESSING"}, []string{
		historyResult.History[0].ToStatus,
		historyResult.History[1].ToStatus,
	})
}

func TestMCP_MalaysiaPDPADPIAScreening_UpdateProcessingActivity(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	mc := testutil.NewMCPClient(t, owner)
	input := mcpAddProcessingActivityInput(owner.GetOrganizationID().String(), factory.SafeName("Malaysia DPIA"))

	var addResult struct {
		ProcessingActivity struct {
			ID string `json:"id"`
		} `json:"processing_activity"`
	}
	mc.CallToolInto("addProcessingActivity", input, &addResult)
	require.NotEmpty(t, addResult.ProcessingActivity.ID)

	var updateResult struct {
		ProcessingActivity struct {
			Recommendation string   `json:"malaysia_pdpa_dpia_recommendation"`
			Reasons        []string `json:"malaysia_pdpa_dpia_reasons"`
			RuleVersion    *string  `json:"malaysia_pdpa_dpia_rule_version"`
			RuleSource     *string  `json:"malaysia_pdpa_dpia_rule_source"`
		} `json:"processing_activity"`
	}
	mc.CallToolInto("updateProcessingActivity", map[string]any{
		"id": addResult.ProcessingActivity.ID,
		"malaysia_pdpa_dpia_screening": map[string]any{
			"total_data_subjects":                  20_001,
			"sensitive_data_subjects":              1_000,
			"legal_or_significant_effects":         false,
			"systematic_monitoring":                false,
			"innovative_technology":                false,
			"denial_or_restriction_of_rights":      false,
			"location_or_behaviour_tracking":       false,
			"children_or_vulnerable_data_subjects": false,
			"high_risk_automated_decision_making":  false,
		},
	}, &updateResult)

	assert.Equal(t, "REQUIRED", updateResult.ProcessingActivity.Recommendation)
	assert.Equal(t, []string{"PERSONAL_DATA_VOLUME"}, updateResult.ProcessingActivity.Reasons)
	require.NotNil(t, updateResult.ProcessingActivity.RuleVersion)
	require.NotNil(t, updateResult.ProcessingActivity.RuleSource)
	assert.NotEmpty(t, *updateResult.ProcessingActivity.RuleVersion)
	assert.Contains(t, *updateResult.ProcessingActivity.RuleSource, "pdp.gov.my")
}

func TestMCP_MalaysiaPDPATransfer_Create(t *testing.T) {
	t.Parallel()

	owner := testutil.NewClient(t, testutil.RoleOwner)
	mc := testutil.NewMCPClient(t, owner)
	organizationID := owner.GetOrganizationID().String()

	var thirdPartyResult struct {
		ThirdParty struct {
			ID string `json:"id"`
		} `json:"thirdParty"`
	}
	mc.CallToolInto("addThirdParty", map[string]any{
		"organization_id": organizationID,
		"name":            factory.SafeName("Malaysia transfer recipient"),
	}, &thirdPartyResult)
	require.NotEmpty(t, thirdPartyResult.ThirdParty.ID)

	processingActivityInput := mcpAddProcessingActivityInput(organizationID, factory.SafeName("Malaysia transfer"))
	processingActivityInput["international_transfers"] = true

	var processingActivityResult struct {
		ProcessingActivity struct {
			ID string `json:"id"`
		} `json:"processing_activity"`
	}
	mc.CallToolInto("addProcessingActivity", processingActivityInput, &processingActivityResult)
	require.NotEmpty(t, processingActivityResult.ProcessingActivity.ID)

	var transferResult struct {
		TransferImpactAssessment struct {
			Basis               *string    `json:"malaysia_transfer_basis"`
			ApprovedByProfileID *string    `json:"malaysia_approved_by_profile_id"`
			NextReviewAt        *time.Time `json:"malaysia_next_review_at"`
			RuleVersion         *string    `json:"malaysia_rule_version"`
			RuleSource          *string    `json:"malaysia_rule_source"`
		} `json:"transfer_impact_assessment"`
	}
	mc.CallToolInto("addTransferImpactAssessment", map[string]any{
		"processing_activity_id": processingActivityResult.ProcessingActivity.ID,
		"malaysia_pdpa": map[string]any{
			"basis":                    "SUBSTANTIALLY_SIMILAR_LAW",
			"destination_country":      "SG",
			"recipient_third_party_id": thirdPartyResult.ThirdParty.ID,
			"receiver_contact":         "privacy@example.com",
			"transfer_purpose":         "Regional customer support",
			"personal_data_categories": "Customer contact details",
			"safeguards":               "Contractual and technical controls",
			"approval_status":          "APPROVED",
			"review_evidence":          "Legal and security review completed",
		},
	}, &transferResult)

	require.NotNil(t, transferResult.TransferImpactAssessment.Basis)
	assert.Equal(t, "SUBSTANTIALLY_SIMILAR_LAW", *transferResult.TransferImpactAssessment.Basis)
	require.NotNil(t, transferResult.TransferImpactAssessment.ApprovedByProfileID)
	assert.Equal(t, owner.GetProfileID().String(), *transferResult.TransferImpactAssessment.ApprovedByProfileID)
	require.NotNil(t, transferResult.TransferImpactAssessment.NextReviewAt)
	require.NotNil(t, transferResult.TransferImpactAssessment.RuleVersion)
	require.NotNil(t, transferResult.TransferImpactAssessment.RuleSource)
}
