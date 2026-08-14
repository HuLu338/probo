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

package view

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"go.probo.inc/probo/pkg/cli/api"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
)

const viewQuery = `
query($id: ID!) {
  node(id: $id) {
    __typename
    ... on ProcessingActivity {
      id
      name
      purpose
      role
      lawfulBasis
      malaysiaPDPADPIATotalDataSubjects
      malaysiaPDPADPIASensitiveDataSubjects
      malaysiaPDPADPIALegalOrSignificantEffects
      malaysiaPDPADPIASystematicMonitoring
      malaysiaPDPADPIAInnovativeTechnology
      malaysiaPDPADPIADenialOrRestrictionOfRights
      malaysiaPDPADPIALocationOrBehaviourTracking
      malaysiaPDPADPIAChildrenOrVulnerableDataSubjects
      malaysiaPDPADPIAHighRiskAutomatedDecisionMaking
      malaysiaPDPADPIAOtherHighRiskFactors
      malaysiaPDPADPIARecommendation
      malaysiaPDPADPIAReasons
      malaysiaPDPADPIAAssessedByProfileId
      malaysiaPDPADPIAAssessedAt
      malaysiaPDPADPIARuleVersion
      malaysiaPDPADPIARuleSource
      createdAt
      updatedAt
    }
  }
}
`

type viewResponse struct {
	Node *struct {
		Typename                                         string   `json:"__typename"`
		ID                                               string   `json:"id"`
		Name                                             string   `json:"name"`
		Purpose                                          *string  `json:"purpose"`
		Role                                             string   `json:"role"`
		LawfulBasis                                      string   `json:"lawfulBasis"`
		MalaysiaPDPADPIATotalDataSubjects                int64    `json:"malaysiaPDPADPIATotalDataSubjects"`
		MalaysiaPDPADPIASensitiveDataSubjects            int64    `json:"malaysiaPDPADPIASensitiveDataSubjects"`
		MalaysiaPDPADPIALegalOrSignificantEffects        bool     `json:"malaysiaPDPADPIALegalOrSignificantEffects"`
		MalaysiaPDPADPIASystematicMonitoring             bool     `json:"malaysiaPDPADPIASystematicMonitoring"`
		MalaysiaPDPADPIAInnovativeTechnology             bool     `json:"malaysiaPDPADPIAInnovativeTechnology"`
		MalaysiaPDPADPIADenialOrRestrictionOfRights      bool     `json:"malaysiaPDPADPIADenialOrRestrictionOfRights"`
		MalaysiaPDPADPIALocationOrBehaviourTracking      bool     `json:"malaysiaPDPADPIALocationOrBehaviourTracking"`
		MalaysiaPDPADPIAChildrenOrVulnerableDataSubjects bool     `json:"malaysiaPDPADPIAChildrenOrVulnerableDataSubjects"`
		MalaysiaPDPADPIAHighRiskAutomatedDecisionMaking  bool     `json:"malaysiaPDPADPIAHighRiskAutomatedDecisionMaking"`
		MalaysiaPDPADPIAOtherHighRiskFactors             *string  `json:"malaysiaPDPADPIAOtherHighRiskFactors"`
		MalaysiaPDPADPIARecommendation                   string   `json:"malaysiaPDPADPIARecommendation"`
		MalaysiaPDPADPIAReasons                          []string `json:"malaysiaPDPADPIAReasons"`
		MalaysiaPDPADPIAAssessedByProfileID              *string  `json:"malaysiaPDPADPIAAssessedByProfileId"`
		MalaysiaPDPADPIAAssessedAt                       *string  `json:"malaysiaPDPADPIAAssessedAt"`
		MalaysiaPDPADPIARuleVersion                      *string  `json:"malaysiaPDPADPIARuleVersion"`
		MalaysiaPDPADPIARuleSource                       *string  `json:"malaysiaPDPADPIARuleSource"`
		CreatedAt                                        string   `json:"createdAt"`
		UpdatedAt                                        string   `json:"updatedAt"`
	} `json:"node"`
}

func NewCmdView(f *cmdutil.Factory) *cobra.Command {
	var flagOutput *string

	cmd := &cobra.Command{
		Use:   "view <id>",
		Short: "View a processing activity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmdutil.ValidateOutputFlag(flagOutput); err != nil {
				return err
			}

			cfg, err := f.Config()
			if err != nil {
				return err
			}

			host, hc, err := cfg.DefaultHost()
			if err != nil {
				return err
			}

			client := api.NewClient(
				host,
				hc.Token,
				"/api/console/v1/graphql",
				cfg.HTTPTimeoutDuration(),
				cmdutil.TokenRefreshOption(cfg, host, hc),
			)

			data, err := client.Do(
				viewQuery,
				map[string]any{"id": args[0]},
			)
			if err != nil {
				return err
			}

			var resp viewResponse
			if err := json.Unmarshal(data, &resp); err != nil {
				return fmt.Errorf("cannot parse response: %w", err)
			}

			if resp.Node == nil {
				return fmt.Errorf("processing activity %s not found", args[0])
			}

			if resp.Node.Typename != "ProcessingActivity" {
				return fmt.Errorf("expected ProcessingActivity node, got %s", resp.Node.Typename)
			}

			if *flagOutput == cmdutil.OutputJSON {
				return cmdutil.PrintJSON(f.IOStreams.Out, resp.Node)
			}

			a := resp.Node
			out := f.IOStreams.Out

			bold := lipgloss.NewStyle().Bold(true)
			label := lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Width(22)

			_, _ = fmt.Fprintf(out, "%s\n\n", bold.Render(a.Name))

			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("ID:"), a.ID)
			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Role:"), a.Role)
			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Lawful Basis:"), a.LawfulBasis)

			if a.Purpose != nil && *a.Purpose != "" {
				_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Purpose:"), *a.Purpose)
			}

			if a.MalaysiaPDPADPIAAssessedAt != nil {
				malaysiaLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Width(44)

				_, _ = fmt.Fprintln(out)
				_, _ = fmt.Fprintln(out, bold.Render("Malaysia PDPA DPIA Screening"))
				_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Recommendation:"), a.MalaysiaPDPADPIARecommendation)
				_, _ = fmt.Fprintf(out, "%s%d\n", malaysiaLabel.Render("Total Data Subjects:"), a.MalaysiaPDPADPIATotalDataSubjects)
				_, _ = fmt.Fprintf(out, "%s%d\n", malaysiaLabel.Render("Sensitive Data Subjects:"), a.MalaysiaPDPADPIASensitiveDataSubjects)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("Legal or Significant Effects:"), a.MalaysiaPDPADPIALegalOrSignificantEffects)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("Systematic Monitoring:"), a.MalaysiaPDPADPIASystematicMonitoring)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("Innovative Technology:"), a.MalaysiaPDPADPIAInnovativeTechnology)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("Denial or Restriction of Rights:"), a.MalaysiaPDPADPIADenialOrRestrictionOfRights)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("Location or Behaviour Tracking:"), a.MalaysiaPDPADPIALocationOrBehaviourTracking)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("Children or Vulnerable Data Subjects:"), a.MalaysiaPDPADPIAChildrenOrVulnerableDataSubjects)
				_, _ = fmt.Fprintf(out, "%s%t\n", malaysiaLabel.Render("High-Risk Automated Decision Making:"), a.MalaysiaPDPADPIAHighRiskAutomatedDecisionMaking)

				if a.MalaysiaPDPADPIAOtherHighRiskFactors != nil && *a.MalaysiaPDPADPIAOtherHighRiskFactors != "" {
					_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Other High-Risk Factors:"), *a.MalaysiaPDPADPIAOtherHighRiskFactors)
				}

				if len(a.MalaysiaPDPADPIAReasons) > 0 {
					_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Reasons:"), strings.Join(a.MalaysiaPDPADPIAReasons, ", "))
				}

				if a.MalaysiaPDPADPIAAssessedByProfileID != nil {
					_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Assessed By Profile ID:"), *a.MalaysiaPDPADPIAAssessedByProfileID)
				}

				_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Assessed:"), cmdutil.FormatTime(*a.MalaysiaPDPADPIAAssessedAt))

				if a.MalaysiaPDPADPIARuleVersion != nil {
					_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Rule Version:"), *a.MalaysiaPDPADPIARuleVersion)
				}

				if a.MalaysiaPDPADPIARuleSource != nil {
					_, _ = fmt.Fprintf(out, "%s%s\n", malaysiaLabel.Render("Rule Source:"), *a.MalaysiaPDPADPIARuleSource)
				}
			}

			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Created:"), cmdutil.FormatTime(a.CreatedAt))
			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Updated:"), cmdutil.FormatTime(a.UpdatedAt))

			return nil
		},
	}

	flagOutput = cmdutil.AddOutputFlag(cmd)

	return cmd
}
