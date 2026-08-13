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

package ingest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"go.probo.inc/probo/pkg/cli/api"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
)

const ingestMutation = `
mutation($input: IngestMalaysiaPDPAScannerFindingInput!) {
  ingestMalaysiaPDPAScannerFinding(input: $input) {
    created
    scannerFinding {
      id
      organizationId
      externalId
      source
      checkKey
      severity
      summary
      evidence
      observedAt
      ruleVersion
      ruleSource
      createdAt
      updatedAt
    }
    finding {
      id
      referenceId
      kind
      priority
      status
    }
  }
}
`

type ingestResponse struct {
	IngestMalaysiaPDPAScannerFinding struct {
		Created        bool `json:"created"`
		ScannerFinding struct {
			ID             string    `json:"id"`
			OrganizationID string    `json:"organizationId"`
			ExternalID     string    `json:"externalId"`
			Source         string    `json:"source"`
			CheckKey       string    `json:"checkKey"`
			Severity       string    `json:"severity"`
			Summary        string    `json:"summary"`
			Evidence       string    `json:"evidence"`
			ObservedAt     time.Time `json:"observedAt"`
			RuleVersion    string    `json:"ruleVersion"`
			RuleSource     string    `json:"ruleSource"`
			CreatedAt      time.Time `json:"createdAt"`
			UpdatedAt      time.Time `json:"updatedAt"`
		} `json:"scannerFinding"`
		Finding struct {
			ID          string `json:"id"`
			ReferenceID string `json:"referenceId"`
			Kind        string `json:"kind"`
			Priority    string `json:"priority"`
			Status      string `json:"status"`
		} `json:"finding"`
	} `json:"ingestMalaysiaPDPAScannerFinding"`
}

func NewCmdIngest(f *cmdutil.Factory) *cobra.Command {
	var (
		flagOrg         string
		flagExternalID  string
		flagSource      string
		flagCheckKey    string
		flagSeverity    string
		flagSummary     string
		flagEvidence    string
		flagObservedAt  string
		flagRuleVersion string
		flagRuleSource  string
		flagOutput      *string
	)

	cmd := &cobra.Command{
		Use:     "ingest",
		Short:   "Create or update a Malaysia PDPA scanner finding",
		Example: `  prb malaysia-pdpa scanner ingest --org <org-id> --external-id scan-001 --source openlist --check-key TLS --severity HIGH --summary "TLS configuration is weak" --evidence '{"protocol":"TLSv1.0"}' --observed-at 2026-08-12T03:00:00Z --rule-version 2026.08 --rule-source https://scanner.example/rules/tls`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmdutil.ValidateOutputFlag(flagOutput); err != nil {
				return err
			}

			observedAt, err := time.Parse(time.RFC3339, flagObservedAt)
			if err != nil {
				return fmt.Errorf("invalid --observed-at: use RFC3339 format: %w", err)
			}

			var evidence map[string]any
			if err := json.Unmarshal([]byte(flagEvidence), &evidence); err != nil || len(evidence) == 0 {
				return fmt.Errorf("--evidence must be a non-empty JSON object")
			}

			cfg, err := f.Config()
			if err != nil {
				return err
			}

			host, hc, err := cfg.DefaultHost()
			if err != nil {
				return err
			}

			organizationID := flagOrg
			if organizationID == "" {
				organizationID = hc.Organization
			}

			if organizationID == "" {
				return fmt.Errorf("organization ID is required: pass --org or run `prb auth login`")
			}

			client := api.NewClient(
				host,
				hc.Token,
				"/api/console/v1/graphql",
				cfg.HTTPTimeoutDuration(),
				cmdutil.TokenRefreshOption(cfg, host, hc),
			)

			data, err := client.Do(ingestMutation, map[string]any{
				"input": map[string]any{
					"organizationId": organizationID,
					"externalId":     flagExternalID,
					"source":         flagSource,
					"checkKey":       flagCheckKey,
					"severity":       flagSeverity,
					"summary":        flagSummary,
					"evidence":       flagEvidence,
					"observedAt":     observedAt.Format(time.RFC3339),
					"ruleVersion":    flagRuleVersion,
					"ruleSource":     flagRuleSource,
				},
			})
			if err != nil {
				return err
			}

			var response ingestResponse
			if err := json.Unmarshal(data, &response); err != nil {
				return fmt.Errorf("cannot parse response: %w", err)
			}

			result := response.IngestMalaysiaPDPAScannerFinding
			if *flagOutput == cmdutil.OutputJSON {
				return cmdutil.PrintJSON(f.IOStreams.Out, result)
			}

			action := "Updated"
			if result.Created {
				action = "Created"
			}

			_, _ = fmt.Fprintf(
				f.IOStreams.Out,
				"%s scanner finding %s and compliance finding %s (%s)\n",
				action,
				result.ScannerFinding.ID,
				result.Finding.ReferenceID,
				result.Finding.Priority,
			)

			return nil
		},
	}

	cmd.Flags().StringVar(&flagOrg, "org", "", "Organization ID")
	cmd.Flags().StringVar(&flagExternalID, "external-id", "", "Stable scanner-side finding ID")
	cmd.Flags().StringVar(&flagSource, "source", "", "Stable scanner integration name")
	cmd.Flags().StringVar(&flagCheckKey, "check-key", "", "Scanner check key")
	cmd.Flags().StringVar(&flagSeverity, "severity", "", "Finding severity: LOW, MEDIUM, HIGH, or CRITICAL")
	cmd.Flags().StringVar(&flagSummary, "summary", "", "Finding summary")
	cmd.Flags().StringVar(&flagEvidence, "evidence", "", "Non-empty JSON evidence object")
	cmd.Flags().StringVar(&flagObservedAt, "observed-at", "", "Observation time in RFC3339 format")
	cmd.Flags().StringVar(&flagRuleVersion, "rule-version", "", "Scanner rule version")
	cmd.Flags().StringVar(&flagRuleSource, "rule-source", "", "Scanner rule source")
	flagOutput = cmdutil.AddOutputFlag(cmd)

	for _, name := range []string{
		"external-id",
		"source",
		"check-key",
		"severity",
		"summary",
		"evidence",
		"observed-at",
		"rule-version",
		"rule-source",
	} {
		_ = cmd.MarkFlagRequired(name)
	}

	return cmd
}
