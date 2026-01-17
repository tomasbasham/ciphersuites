package ciphersuites_test

import (
	"testing"

	"github.com/tomasbasham/ciphersuites"
)

func TestGetCipherSuite(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite string
		expected    ciphersuites.CipherSuite
	}{
		"returns recommended": {
			cipherSuite: "TLS_AES_128_CCM_SHA256",
			expected: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "AES 128 CCM",
				HashAlgorithm:       "SHA256",
				Classification:      ciphersuites.Recommended,
				TLSVersions:         []string{"TLS1.3"},
			},
		},
		"returns secure": {
			cipherSuite: "TLS_AES_128_CCM_8_SHA256",
			expected: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "AES 128 CCM 8",
				HashAlgorithm:       "SHA256",
				Classification:      ciphersuites.Secure,
				TLSVersions:         []string{"TLS1.3"},
			},
		},
		"returns weak": {
			cipherSuite: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
			expected: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "3DES EDE CBC",
				HashAlgorithm:       "SHA",
				Classification:      ciphersuites.Weak,
				TLSVersions:         []string{"TLS1.0", "TLS1.1", "TLS1.2", "SSL1.3"},
			},
		},
		"returns insecure": {
			cipherSuite: "TLS_DH_anon_WITH_RC4_128_MD5",
			expected: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "RC4 128",
				HashAlgorithm:       "MD5",
				Classification:      ciphersuites.Insecure,
				TLSVersions:         []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"},
			},
		},
		"returns unknown": {
			cipherSuite: "UNKNOWN_CIPHER_SUITE",
			expected: ciphersuites.CipherSuite{
				ProtocolVersion:     "",
				EncryptionAlgorithm: "",
				HashAlgorithm:       "",
				Classification:      ciphersuites.Unknown,
				TLSVersions:         nil,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cipherSuite, ok := ciphersuites.GetCipherSuite(tt.cipherSuite)
			if !ok && tt.expected.Classification != ciphersuites.Unknown {
				t.Fatal("cipher suite not found")
			}
			if !cipherSuiteEqual(cipherSuite, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, cipherSuite)
			}
		})
	}
}

func TestIsRecommended(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		expected    bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Recommended,
			},
			expected: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			expected:    false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if recommended := tt.cipherSuite.IsRecommended(); recommended != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, recommended)
			}
		})
	}
}

func TestIsSecure(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		expected    bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Secure,
			},
			expected: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			expected:    false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if secure := tt.cipherSuite.IsSecure(); secure != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, secure)
			}
		})
	}
}

func TestIsWeak(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		expected    bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Weak,
			},
			expected: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			expected:    false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if weak := tt.cipherSuite.IsWeak(); weak != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, weak)
			}
		})
	}
}

func TestIsInsecure(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		expected    bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Insecure,
			},
			expected: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			expected:    false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if insecure := tt.cipherSuite.IsInsecure(); insecure != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, insecure)
			}
		})
	}
}

func cipherSuiteEqual(a, b ciphersuites.CipherSuite) bool {
	return a.ProtocolVersion == b.ProtocolVersion &&
		a.EncryptionAlgorithm == b.EncryptionAlgorithm &&
		a.HashAlgorithm == b.HashAlgorithm &&
		a.Classification == b.Classification
}
