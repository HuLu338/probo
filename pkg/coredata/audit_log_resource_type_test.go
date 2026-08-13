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

package coredata_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.probo.inc/probo/pkg/coredata"
)

func TestResourceTypeName_MalaysiaPDPAEntities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entityType uint16
		expected   string
	}{
		{name: "breach incident", entityType: coredata.MalaysiaPDPABreachIncidentEntityType, expected: "MalaysiaPDPABreachIncident"},
		{name: "breach status history", entityType: coredata.MalaysiaPDPABreachStatusHistoryEntityType, expected: "MalaysiaPDPABreachStatusHistory"},
		{name: "scanner finding", entityType: coredata.MalaysiaPDPAScannerFindingEntityType, expected: "MalaysiaPDPAScannerFinding"},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				assert.Equal(t, tt.expected, coredata.ResourceTypeName(tt.entityType))
			},
		)
	}
}
