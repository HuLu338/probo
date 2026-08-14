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

package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenFromMailpitMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		text     string
		expected string
	}{
		{
			name:     "token link in plain text",
			text:     "Open http://localhost:18080/auth/verify-email?token=confirmation-token to continue.",
			expected: "confirmation-token",
		},
		{
			name:     "token link wrapped in angle brackets",
			text:     "Invitation: <http://localhost:18080/auth/activate?token=activation-token>",
			expected: "activation-token",
		},
		{
			name: "message without token link",
			text: "Visit https://www.probo.com for more information.",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				t.Parallel()

				message := &MailpitMessageDetail{Text: tt.text}
				assert.Equal(t, tt.expected, tokenFromMailpitMessage(message))
			},
		)
	}
}
