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

package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/cli/config"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
	"go.probo.inc/probo/pkg/cmd/iostreams"
)

func TestNewCmdUpdate_RequestsDPOAssessmentProvenance(t *testing.T) {
	t.Parallel()

	queries := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Query string `json:"query"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		queries <- request.Query

		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(request.Query, "query($id: ID!)") {
			_, _ = w.Write([]byte(`{"data":{"node":{"malaysiaPDPAProfile":{}}}}`))
			return
		}

		_, _ = w.Write([]byte(`{"data":{"updateMalaysiaPDPAProfile":{"malaysiaPDPAProfile":{"organizationId":"organization-id","dpoRequired":true,"dpoRequirementReasons":["PERSONAL_DATA_VOLUME"],"assessedAt":"2026-08-13T12:00:00Z","ruleVersion":"MY-PDPA-DPO-2025-06-01","ruleSource":"https://www.pdp.gov.my/ppdpv1/wp-content/uploads/2025/08/GP_DPO_ENG.pdf"}}}}`))
	}))
	t.Cleanup(server.Close)

	streams, _, _ := iostreams.Test()
	cfg := &config.Config{
		ActiveHost: server.URL,
		Hosts: map[string]*config.HostConfig{
			server.URL: {Token: "token", Organization: "organization-id"},
		},
	}
	cmd := NewCmdUpdate(&cmdutil.Factory{
		IOStreams: streams,
		Config: func() (*config.Config, error) {
			return cfg, nil
		},
	})
	cmd.SetArgs([]string{
		"--org", "organization-id",
		"--total-data-subjects", "20001",
		"--sensitive-data-subjects", "10000",
		"--regular-systematic-monitoring=false",
	})

	require.NoError(t, cmd.Execute())
	<-queries
	mutation := <-queries
	assert.Contains(t, mutation, "ruleVersion")
	assert.Contains(t, mutation, "ruleSource")
}
