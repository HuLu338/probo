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

package types_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.probo.inc/probo/pkg/coredata"
	"go.probo.inc/probo/pkg/server/api/mcp/v1/types"
)

func TestNewMalaysiaPDPABreachIncident_PhasedInformationOverdue(t *testing.T) {
	t.Parallel()

	commissionerNotifiedAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)
	phasedInformationDueAt := commissionerNotifiedAt.Add(30 * 24 * time.Hour)
	confirmationAfterDeadline := phasedInformationDueAt.Add(time.Second)

	tests := []struct {
		name                   string
		confirmationReceivedAt *time.Time
		expectedOverdue        bool
	}{
		{name: "unconfirmed after deadline", confirmationReceivedAt: nil, expectedOverdue: true},
		{name: "confirmed exactly at deadline", confirmationReceivedAt: &phasedInformationDueAt, expectedOverdue: false},
		{name: "confirmed one second after deadline", confirmationReceivedAt: &confirmationAfterDeadline, expectedOverdue: true},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				incident := types.NewMalaysiaPDPABreachIncident(&coredata.MalaysiaPDPABreachIncident{
					AwarenessAt:                        commissionerNotifiedAt.Add(-24 * time.Hour),
					AffectedDataSubjects:               1_001,
					NotificationDecision:               coredata.MalaysiaPDPABreachNotificationDecisionCommissionerOnly,
					CommissionerNotifiedAt:             &commissionerNotifiedAt,
					CommissionerConfirmationReceivedAt: tt.confirmationReceivedAt,
				})

				require.NotNil(t, incident.PhasedInformationDueAt)
				assert.Equal(t, phasedInformationDueAt, *incident.PhasedInformationDueAt)
				assert.Equal(t, tt.expectedOverdue, incident.PhasedInformationOverdue)
			},
		)
	}
}
