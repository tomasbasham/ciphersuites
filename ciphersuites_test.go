package ciphersuites_test

import (
	"testing"

	"github.com/tomasbasham/ciphersuites"
)

func TestGetCipherSuite(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite string
		want        ciphersuites.CipherSuite
	}{
		"returns recommended": {
			cipherSuite: "TLS_AES_128_CCM_SHA256",
			want: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "AES 128 CCM",
				HashAlgorithm:       "SHA256",
				Classification:      ciphersuites.Recommended,
				TLSVersions:         []string{"TLS1.3"},
			},
		},
		"returns secure": {
			cipherSuite: "TLS_AES_128_CCM_8_SHA256",
			want: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "AES 128 CCM 8",
				HashAlgorithm:       "SHA256",
				Classification:      ciphersuites.Secure,
				TLSVersions:         []string{"TLS1.3"},
			},
		},
		"returns weak": {
			cipherSuite: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
			want: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "CAMELLIA 256 CBC",
				HashAlgorithm:       "SHA",
				Classification:      ciphersuites.Weak,
				TLSVersions:         []string{"TLS1.0", "TLS1.1", "TLS1.2", "SSL1.3"},
			},
		},
		"returns insecure": {
			cipherSuite: "TLS_DH_anon_WITH_RC4_128_MD5",
			want: ciphersuites.CipherSuite{
				ProtocolVersion:     "TLS",
				EncryptionAlgorithm: "RC4 128",
				HashAlgorithm:       "MD5",
				Classification:      ciphersuites.Insecure,
				TLSVersions:         []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"},
			},
		},
		"returns unknown": {
			cipherSuite: "UNKNOWN_CIPHER_SUITE",
			want: ciphersuites.CipherSuite{
				ProtocolVersion:     "",
				EncryptionAlgorithm: "",
				HashAlgorithm:       "",
				Classification:      ciphersuites.Unknown,
				TLSVersions:         nil,
			},
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := ciphersuites.GetCipherSuite(tt.cipherSuite)
			if !ok && tt.want.Classification != ciphersuites.Unknown {
				t.Fatal("cipher suite not found")
			}
			if !cipherSuiteEqual(got, tt.want) {
				t.Errorf("mismatch:\n  got:  %#v\n  want: %#v", got, tt.want)
			}
		})
	}
}

func TestIsRecommended(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		want        bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Recommended,
			},
			want: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			want:        false,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cipherSuite.IsRecommended()
			if got != tt.want {
				t.Errorf("mismatch:\n  got:  %t\n  want: %t", got, tt.want)
			}
		})
	}
}

func TestIsSecure(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		want        bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Secure,
			},
			want: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			want:        false,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cipherSuite.IsSecure()
			if got != tt.want {
				t.Errorf("mismatch:\n  got:  %t\n  want: %t", got, tt.want)
			}
		})
	}
}

func TestIsWeak(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		want        bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Weak,
			},
			want: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			want:        false,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cipherSuite.IsWeak()
			if got != tt.want {
				t.Errorf("mismatch:\n  got:  %t\n  want: %t", got, tt.want)
			}
		})
	}
}

func TestIsInsecure(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite ciphersuites.CipherSuite
		want        bool
	}{
		"returns true": {
			cipherSuite: ciphersuites.CipherSuite{
				Classification: ciphersuites.Insecure,
			},
			want: true,
		},
		"returns false": {
			cipherSuite: ciphersuites.CipherSuite{},
			want:        false,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cipherSuite.IsInsecure()
			if got != tt.want {
				t.Errorf("mismatch:\n  got:  %t\n  want: %t", got, tt.want)
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
