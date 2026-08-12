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

package coredata

import (
	"encoding"
	"fmt"
)

type MalaysiaPDPAScannerFindingSeverity string

const (
	MalaysiaPDPAScannerFindingSeverityLow      MalaysiaPDPAScannerFindingSeverity = "LOW"
	MalaysiaPDPAScannerFindingSeverityMedium   MalaysiaPDPAScannerFindingSeverity = "MEDIUM"
	MalaysiaPDPAScannerFindingSeverityHigh     MalaysiaPDPAScannerFindingSeverity = "HIGH"
	MalaysiaPDPAScannerFindingSeverityCritical MalaysiaPDPAScannerFindingSeverity = "CRITICAL"
)

var (
	_ fmt.Stringer             = MalaysiaPDPAScannerFindingSeverity("")
	_ encoding.TextMarshaler   = MalaysiaPDPAScannerFindingSeverity("")
	_ encoding.TextUnmarshaler = (*MalaysiaPDPAScannerFindingSeverity)(nil)
)

func MalaysiaPDPAScannerFindingSeverities() []MalaysiaPDPAScannerFindingSeverity {
	return []MalaysiaPDPAScannerFindingSeverity{
		MalaysiaPDPAScannerFindingSeverityLow,
		MalaysiaPDPAScannerFindingSeverityMedium,
		MalaysiaPDPAScannerFindingSeverityHigh,
		MalaysiaPDPAScannerFindingSeverityCritical,
	}
}

func (v MalaysiaPDPAScannerFindingSeverity) IsValid() bool {
	switch v {
	case MalaysiaPDPAScannerFindingSeverityLow,
		MalaysiaPDPAScannerFindingSeverityMedium,
		MalaysiaPDPAScannerFindingSeverityHigh,
		MalaysiaPDPAScannerFindingSeverityCritical:
		return true
	}

	return false
}

func (v MalaysiaPDPAScannerFindingSeverity) String() string {
	return string(v)
}

func (v MalaysiaPDPAScannerFindingSeverity) MarshalText() ([]byte, error) {
	return []byte(v.String()), nil
}

func (v *MalaysiaPDPAScannerFindingSeverity) UnmarshalText(text []byte) error {
	value := MalaysiaPDPAScannerFindingSeverity(text)
	if !value.IsValid() {
		return fmt.Errorf("invalid MalaysiaPDPAScannerFindingSeverity value: %q", string(text))
	}

	*v = value

	return nil
}
