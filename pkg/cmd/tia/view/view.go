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

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"go.probo.inc/probo/pkg/cli/api"
	"go.probo.inc/probo/pkg/cmd/cmdutil"
)

const viewQuery = `
query($id: ID!) {
  node(id: $id) {
    __typename
    ... on TransferImpactAssessment {
      id
      dataSubjects
      legalMechanism
      transfer
      localLawRisk
      supplementaryMeasures
      malaysiaTransferBasis
      malaysiaDestinationCountry
      malaysiaRecipientThirdPartyId
      malaysiaReceiverRegistrationNumber
      malaysiaReceiverContact
      malaysiaTransferPurpose
      malaysiaPersonalDataCategories
      malaysiaSafeguards
      malaysiaApprovalStatus
      malaysiaApprovedByProfileId
      malaysiaApprovalNotes
      malaysiaReviewedAt
      malaysiaNextReviewAt
      malaysiaReviewEvidence
      malaysiaRuleVersion
      malaysiaRuleSource
      createdAt
      updatedAt
    }
  }
}
`

type viewResponse struct {
	Node *struct {
		Typename                           string  `json:"__typename"`
		ID                                 string  `json:"id"`
		DataSubjects                       string  `json:"dataSubjects"`
		LegalMechanism                     string  `json:"legalMechanism"`
		Transfer                           string  `json:"transfer"`
		LocalLawRisk                       string  `json:"localLawRisk"`
		SupplementaryMeasures              string  `json:"supplementaryMeasures"`
		MalaysiaTransferBasis              *string `json:"malaysiaTransferBasis"`
		MalaysiaDestinationCountry         *string `json:"malaysiaDestinationCountry"`
		MalaysiaRecipientThirdPartyID      *string `json:"malaysiaRecipientThirdPartyId"`
		MalaysiaReceiverRegistrationNumber *string `json:"malaysiaReceiverRegistrationNumber"`
		MalaysiaReceiverContact            *string `json:"malaysiaReceiverContact"`
		MalaysiaTransferPurpose            *string `json:"malaysiaTransferPurpose"`
		MalaysiaPersonalDataCategories     *string `json:"malaysiaPersonalDataCategories"`
		MalaysiaSafeguards                 *string `json:"malaysiaSafeguards"`
		MalaysiaApprovalStatus             *string `json:"malaysiaApprovalStatus"`
		MalaysiaApprovedByProfileID        *string `json:"malaysiaApprovedByProfileId"`
		MalaysiaApprovalNotes              *string `json:"malaysiaApprovalNotes"`
		MalaysiaReviewedAt                 *string `json:"malaysiaReviewedAt"`
		MalaysiaNextReviewAt               *string `json:"malaysiaNextReviewAt"`
		MalaysiaReviewEvidence             *string `json:"malaysiaReviewEvidence"`
		MalaysiaRuleVersion                *string `json:"malaysiaRuleVersion"`
		MalaysiaRuleSource                 *string `json:"malaysiaRuleSource"`
		CreatedAt                          string  `json:"createdAt"`
		UpdatedAt                          string  `json:"updatedAt"`
	} `json:"node"`
}

func NewCmdView(f *cmdutil.Factory) *cobra.Command {
	var flagOutput *string

	cmd := &cobra.Command{
		Use:   "view <id>",
		Short: "View a transfer impact assessment",
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
				return fmt.Errorf("transfer impact assessment %s not found", args[0])
			}

			if resp.Node.Typename != "TransferImpactAssessment" {
				return fmt.Errorf("expected TransferImpactAssessment node, got %s", resp.Node.Typename)
			}

			if *flagOutput == cmdutil.OutputJSON {
				return cmdutil.PrintJSON(f.IOStreams.Out, resp.Node)
			}

			r := resp.Node
			out := f.IOStreams.Out

			bold := lipgloss.NewStyle().Bold(true)
			label := lipgloss.NewStyle().Foreground(lipgloss.Color("242")).Width(26)

			_, _ = fmt.Fprintf(out, "%s\n\n", bold.Render("Transfer Impact Assessment"))

			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("ID:"), r.ID)

			if r.DataSubjects != "" {
				_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Data Subjects:"), r.DataSubjects)
			}

			if r.LegalMechanism != "" {
				_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Legal Mechanism:"), r.LegalMechanism)
			}

			if r.Transfer != "" {
				_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Transfer:"), r.Transfer)
			}

			if r.LocalLawRisk != "" {
				_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Local Law Risk:"), r.LocalLawRisk)
			}

			if r.SupplementaryMeasures != "" {
				_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Supplementary Measures:"), r.SupplementaryMeasures)
			}

			if r.MalaysiaTransferBasis != nil {
				printOptional := func(labelText string, value *string) {
					if value != nil && *value != "" {
						_, _ = fmt.Fprintf(out, "%s%s\n", label.Render(labelText), *value)
					}
				}

				_, _ = fmt.Fprintln(out)
				_, _ = fmt.Fprintln(out, bold.Render("Malaysia PDPA Transfer Record"))
				printOptional("Transfer Basis:", r.MalaysiaTransferBasis)
				printOptional("Destination Country:", r.MalaysiaDestinationCountry)
				printOptional("Recipient Third-Party ID:", r.MalaysiaRecipientThirdPartyID)
				printOptional("Receiver Registration No.:", r.MalaysiaReceiverRegistrationNumber)
				printOptional("Receiver Contact:", r.MalaysiaReceiverContact)
				printOptional("Transfer Purpose:", r.MalaysiaTransferPurpose)
				printOptional("Personal Data Categories:", r.MalaysiaPersonalDataCategories)
				printOptional("Safeguards:", r.MalaysiaSafeguards)
				printOptional("Approval Status:", r.MalaysiaApprovalStatus)
				printOptional("Approved By Profile ID:", r.MalaysiaApprovedByProfileID)
				printOptional("Approval Notes:", r.MalaysiaApprovalNotes)
				printOptional("Review Evidence:", r.MalaysiaReviewEvidence)

				if r.MalaysiaReviewedAt != nil {
					_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Reviewed:"), cmdutil.FormatTime(*r.MalaysiaReviewedAt))
				}

				if r.MalaysiaNextReviewAt != nil {
					_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Next Review:"), cmdutil.FormatTime(*r.MalaysiaNextReviewAt))
				}

				printOptional("Rule Version:", r.MalaysiaRuleVersion)
				printOptional("Rule Source:", r.MalaysiaRuleSource)
			}

			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Created:"), cmdutil.FormatTime(r.CreatedAt))
			_, _ = fmt.Fprintf(out, "%s%s\n", label.Render("Updated:"), cmdutil.FormatTime(r.UpdatedAt))

			return nil
		},
	}

	flagOutput = cmdutil.AddOutputFlag(cmd)

	return cmd
}
