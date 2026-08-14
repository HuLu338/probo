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

package view_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/cli/config"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
	"go.probo.inc/probo/pkg/cmd/iostreams"
	tiaview "go.probo.inc/probo/pkg/cmd/tia/view"
)

func TestNewCmdView_ReturnsMalaysiaPDPATransferFields(t *testing.T) {
	t.Parallel()

	queries := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Query string `json:"query"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))

		queries <- request.Query

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"node":{"__typename":"TransferImpactAssessment","id":"tia-id","dataSubjects":"Customers","legalMechanism":"Section 129","transfer":"Cloud hosting","localLawRisk":"Low","supplementaryMeasures":"Encryption","malaysiaTransferBasis":"ADEQUATE_EQUIVALENT_PROTECTION","malaysiaDestinationCountry":"SG","malaysiaRecipientThirdPartyId":"third-party-id","malaysiaReceiverRegistrationNumber":"SG-123","malaysiaReceiverContact":"dpo@example.com","malaysiaTransferPurpose":"Cloud hosting","malaysiaPersonalDataCategories":"Contact data","malaysiaSafeguards":"Encryption and SCCs","malaysiaApprovalStatus":"APPROVED","malaysiaApprovedByProfileId":"profile-id","malaysiaApprovalNotes":"Approved","malaysiaReviewedAt":"2026-08-14T04:00:00Z","malaysiaNextReviewAt":"2027-08-14T04:00:00Z","malaysiaReviewEvidence":"Legal review","malaysiaRuleVersion":"MY-PDPA-XBORDER-2025-06-01","malaysiaRuleSource":"https://www.pdp.gov.my/","createdAt":"2026-08-14T03:00:00Z","updatedAt":"2026-08-14T04:00:00Z"}}}`))
	}))
	t.Cleanup(server.Close)

	streams, out, _ := iostreams.Test()
	cfg := &config.Config{
		ActiveHost: server.URL,
		Hosts: map[string]*config.HostConfig{
			server.URL: {Token: "token"},
		},
	}
	cmd := tiaview.NewCmdView(&cmdutil.Factory{
		IOStreams: streams,
		Config: func() (*config.Config, error) {
			return cfg, nil
		},
	})
	cmd.SetArgs([]string{"tia-id", "--output", "json"})

	require.NoError(t, cmd.Execute())

	query := <-queries
	for _, field := range []string{
		"malaysiaTransferBasis",
		"malaysiaDestinationCountry",
		"malaysiaRecipientThirdPartyId",
		"malaysiaReceiverRegistrationNumber",
		"malaysiaReceiverContact",
		"malaysiaTransferPurpose",
		"malaysiaPersonalDataCategories",
		"malaysiaSafeguards",
		"malaysiaApprovalStatus",
		"malaysiaApprovedByProfileId",
		"malaysiaApprovalNotes",
		"malaysiaReviewedAt",
		"malaysiaNextReviewAt",
		"malaysiaReviewEvidence",
		"malaysiaRuleVersion",
		"malaysiaRuleSource",
	} {
		assert.Contains(t, query, field)
	}

	var assessment map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &assessment))
	assert.Equal(t, "ADEQUATE_EQUIVALENT_PROTECTION", assessment["malaysiaTransferBasis"])
	assert.Equal(t, "MY-PDPA-XBORDER-2025-06-01", assessment["malaysiaRuleVersion"])
	assert.Equal(t, "third-party-id", assessment["malaysiaRecipientThirdPartyId"])
}
