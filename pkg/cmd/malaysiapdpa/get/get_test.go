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

package get

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
)

func TestNewCmdGet_ReturnsDPOAssessmentProvenance(t *testing.T) {
	t.Parallel()

	queries := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Query string `json:"query"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		queries <- request.Query

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"node":{"malaysiaPDPAProfile":{"organizationId":"organization-id","totalDataSubjects":20001,"sensitiveDataSubjects":10000,"regularSystematicMonitoring":false,"dpoRequired":true,"dpoRequirementReasons":["PERSONAL_DATA_VOLUME"],"ruleVersion":"MY-PDPA-DPO-2025-06-01","ruleSource":"https://www.pdp.gov.my/ppdpv1/wp-content/uploads/2025/08/GP_DPO_ENG.pdf","commissionerNotificationOverdue":false}}}}`))
	}))
	t.Cleanup(server.Close)

	streams, out, _ := iostreams.Test()
	cfg := &config.Config{
		ActiveHost: server.URL,
		Hosts: map[string]*config.HostConfig{
			server.URL: {Token: "token", Organization: "organization-id"},
		},
	}
	cmd := NewCmdGet(&cmdutil.Factory{
		IOStreams: streams,
		Config: func() (*config.Config, error) {
			return cfg, nil
		},
	})
	cmd.SetArgs([]string{"--org", "organization-id", "--output", "json"})

	require.NoError(t, cmd.Execute())
	query := <-queries
	assert.Contains(t, query, "ruleVersion")
	assert.Contains(t, query, "ruleSource")

	var profile map[string]any
	require.NoError(t, json.Unmarshal([]byte(out.String()), &profile))
	assert.Equal(t, "MY-PDPA-DPO-2025-06-01", profile["ruleVersion"])
	assert.Contains(t, profile["ruleSource"], "pdp.gov.my")
}
