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

package importopenlist

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.probo.inc/probo/pkg/cli/api"
	"go.probo.inc/probo/pkg/cli/config"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
	"go.probo.inc/probo/pkg/malaysiapdpa/openlistscanner"
)

const importMutation = `
mutation($input: IngestMalaysiaPDPAScannerFindingInput!) {
  ingestMalaysiaPDPAScannerFinding(input: $input) {
    created
    scannerFinding { id externalId }
    finding { id referenceId priority status }
  }
}
`

type (
	importMutationResponse struct {
		Ingest struct {
			Created        bool `json:"created"`
			ScannerFinding struct {
				ID         string `json:"id"`
				ExternalID string `json:"externalId"`
			} `json:"scannerFinding"`
			Finding struct {
				ID          string `json:"id"`
				ReferenceID string `json:"referenceId"`
				Priority    string `json:"priority"`
				Status      string `json:"status"`
			} `json:"finding"`
		} `json:"ingestMalaysiaPDPAScannerFinding"`
	}

	importedFinding struct {
		Created          bool   `json:"created"`
		ExternalID       string `json:"externalId"`
		ScannerFindingID string `json:"scannerFindingId"`
		FindingID        string `json:"findingId"`
		ReferenceID      string `json:"referenceId"`
		Priority         string `json:"priority"`
		Status           string `json:"status"`
	}

	importResult struct {
		ScanReportID int64             `json:"scanReportId"`
		Imported     int               `json:"imported"`
		Findings     []importedFinding `json:"findings"`
	}

	defaultHostResolver func(*config.Config) (string, *config.HostConfig, error)
)

func NewCmdImportOpenList(f *cmdutil.Factory) *cobra.Command {
	return newCmdImportOpenList(
		f,
		os.Getenv,
		func(cfg *config.Config) (string, *config.HostConfig, error) {
			return cfg.DefaultHost()
		},
	)
}

func newCmdImportOpenList(
	f *cmdutil.Factory,
	getenv func(string) string,
	defaultHost defaultHostResolver,
) *cobra.Command {
	var (
		flagOrg         string
		flagScannerURL  string
		flagTargetID    string
		flagRuleVersion string
		flagRuleSource  string
		flagOutput      *string
	)

	cmd := &cobra.Command{
		Use:     "import-openlist <scan-id>",
		Short:   "Import an OpenList scan report into Probo findings",
		Example: `  OPENLIST_API_KEY=... prb malaysia-pdpa scanner import-openlist 42 --scanner-url http://scanner:8080 --target-id customer-a-openlist --rule-version 2026.08 --rule-source https://scanner.example/rules/openlist --org <org-id>`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmdutil.ValidateOutputFlag(flagOutput); err != nil {
				return err
			}

			scanID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || scanID <= 0 {
				return fmt.Errorf("scan ID must be a positive integer")
			}

			scannerURL := strings.TrimSpace(flagScannerURL)
			if scannerURL == "" {
				scannerURL = strings.TrimSpace(getenv("OPENLIST_SCANNER_URL"))
			}
			if scannerURL == "" {
				return fmt.Errorf("OpenList scanner URL is required: pass --scanner-url or set OPENLIST_SCANNER_URL")
			}

			scannerAPIKey := getenv("OPENLIST_API_KEY")
			if strings.TrimSpace(scannerAPIKey) == "" {
				return fmt.Errorf("OpenList scanner API key is required: set OPENLIST_API_KEY")
			}

			cfg, err := f.Config()
			if err != nil {
				return err
			}

			host, hc, err := defaultHost(cfg)
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

			scannerClient, err := openlistscanner.NewClient(
				scannerURL,
				scannerAPIKey,
				cfg.HTTPTimeoutDuration(),
			)
			if err != nil {
				return err
			}

			report, err := scannerClient.GetScanReport(cmd.Context(), scanID)
			if err != nil {
				return err
			}

			findings, err := openlistscanner.BuildIngestFindings(
				report,
				flagTargetID,
				flagRuleVersion,
				flagRuleSource,
			)
			if err != nil {
				return err
			}

			proboClient := api.NewClient(
				host,
				hc.Token,
				"/api/console/v1/graphql",
				cfg.HTTPTimeoutDuration(),
				cmdutil.TokenRefreshOption(cfg, host, hc),
			)

			result := importResult{
				ScanReportID: report.ID,
				Findings:     make([]importedFinding, 0, len(findings)),
			}
			for _, finding := range findings {
				data, err := proboClient.Do(
					importMutation,
					map[string]any{
						"input": map[string]any{
							"organizationId": organizationID,
							"externalId":     finding.ExternalID,
							"source":         finding.Source,
							"checkKey":       finding.CheckKey.String(),
							"severity":       finding.Severity.String(),
							"summary":        finding.Summary,
							"evidence":       string(finding.Evidence),
							"observedAt":     finding.ObservedAt.Format(time.RFC3339),
							"ruleVersion":    finding.RuleVersion,
							"ruleSource":     finding.RuleSource,
						},
					},
				)
				if err != nil {
					return fmt.Errorf("cannot import OpenList risk %q: %w", finding.ExternalID, err)
				}

				var response importMutationResponse
				if err := json.Unmarshal(data, &response); err != nil {
					return fmt.Errorf("cannot parse imported OpenList finding %q: %w", finding.ExternalID, err)
				}

				result.Findings = append(
					result.Findings,
					importedFinding{
						Created:          response.Ingest.Created,
						ExternalID:       response.Ingest.ScannerFinding.ExternalID,
						ScannerFindingID: response.Ingest.ScannerFinding.ID,
						FindingID:        response.Ingest.Finding.ID,
						ReferenceID:      response.Ingest.Finding.ReferenceID,
						Priority:         response.Ingest.Finding.Priority,
						Status:           response.Ingest.Finding.Status,
					},
				)
			}
			result.Imported = len(result.Findings)

			if *flagOutput == cmdutil.OutputJSON {
				return cmdutil.PrintJSON(f.IOStreams.Out, result)
			}

			if result.Imported == 0 {
				_, _ = fmt.Fprintf(f.IOStreams.Out, "OpenList scan %d has no triggered risks to import\n", report.ID)
				return nil
			}

			_, _ = fmt.Fprintf(
				f.IOStreams.Out,
				"Imported %d OpenList risk(s) from scan %d\n",
				result.Imported,
				report.ID,
			)
			for _, finding := range result.Findings {
				action := "Updated"
				if finding.Created {
					action = "Created"
				}

				_, _ = fmt.Fprintf(
					f.IOStreams.Out,
					"%s %s (%s, %s)\n",
					action,
					finding.ReferenceID,
					finding.Priority,
					finding.ExternalID,
				)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&flagOrg, "org", "", "Organization ID")
	cmd.Flags().StringVar(&flagScannerURL, "scanner-url", "", "OpenList scanner base URL (or OPENLIST_SCANNER_URL)")
	cmd.Flags().StringVar(&flagTargetID, "target-id", "", "Stable opaque identifier for the OpenList deployment")
	cmd.Flags().StringVar(&flagRuleVersion, "rule-version", "", "Version of the OpenList scanner rule set")
	cmd.Flags().StringVar(&flagRuleSource, "rule-source", "", "Source URL for the OpenList scanner rules")
	flagOutput = cmdutil.AddOutputFlag(cmd)

	for _, name := range []string{"target-id", "rule-version", "rule-source"} {
		_ = cmd.MarkFlagRequired(name)
	}

	return cmd
}
