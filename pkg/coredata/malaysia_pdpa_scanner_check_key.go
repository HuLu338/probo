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

type MalaysiaPDPAScannerCheckKey string

const (
	MalaysiaPDPAScannerCheckKeyMFA                     MalaysiaPDPAScannerCheckKey = "MFA"
	MalaysiaPDPAScannerCheckKeyExposedServices         MalaysiaPDPAScannerCheckKey = "EXPOSED_SERVICES"
	MalaysiaPDPAScannerCheckKeyTLS                     MalaysiaPDPAScannerCheckKey = "TLS"
	MalaysiaPDPAScannerCheckKeyTokenLifetime           MalaysiaPDPAScannerCheckKey = "TOKEN_LIFETIME"
	MalaysiaPDPAScannerCheckKeyBackupEvidence          MalaysiaPDPAScannerCheckKey = "BACKUP_EVIDENCE"
	MalaysiaPDPAScannerCheckKeyPrivilegedAccounts      MalaysiaPDPAScannerCheckKey = "PRIVILEGED_ACCOUNTS"
	MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses MalaysiaPDPAScannerCheckKey = "CONFIGURATION_WEAKNESSES"
)

var (
	_ fmt.Stringer             = MalaysiaPDPAScannerCheckKey("")
	_ encoding.TextMarshaler   = MalaysiaPDPAScannerCheckKey("")
	_ encoding.TextUnmarshaler = (*MalaysiaPDPAScannerCheckKey)(nil)
)

func MalaysiaPDPAScannerCheckKeys() []MalaysiaPDPAScannerCheckKey {
	return []MalaysiaPDPAScannerCheckKey{
		MalaysiaPDPAScannerCheckKeyMFA,
		MalaysiaPDPAScannerCheckKeyExposedServices,
		MalaysiaPDPAScannerCheckKeyTLS,
		MalaysiaPDPAScannerCheckKeyTokenLifetime,
		MalaysiaPDPAScannerCheckKeyBackupEvidence,
		MalaysiaPDPAScannerCheckKeyPrivilegedAccounts,
		MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses,
	}
}

func (v MalaysiaPDPAScannerCheckKey) IsValid() bool {
	switch v {
	case MalaysiaPDPAScannerCheckKeyMFA,
		MalaysiaPDPAScannerCheckKeyExposedServices,
		MalaysiaPDPAScannerCheckKeyTLS,
		MalaysiaPDPAScannerCheckKeyTokenLifetime,
		MalaysiaPDPAScannerCheckKeyBackupEvidence,
		MalaysiaPDPAScannerCheckKeyPrivilegedAccounts,
		MalaysiaPDPAScannerCheckKeyConfigurationWeaknesses:
		return true
	}

	return false
}

func (v MalaysiaPDPAScannerCheckKey) String() string {
	return string(v)
}

func (v MalaysiaPDPAScannerCheckKey) MarshalText() ([]byte, error) {
	return []byte(v.String()), nil
}

func (v *MalaysiaPDPAScannerCheckKey) UnmarshalText(text []byte) error {
	value := MalaysiaPDPAScannerCheckKey(text)
	if !value.IsValid() {
		return fmt.Errorf("invalid MalaysiaPDPAScannerCheckKey value: %q", string(text))
	}

	*v = value

	return nil
}
