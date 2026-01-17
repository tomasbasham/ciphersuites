package ciphersuites_test

import (
	"testing"

	"github.com/tomasbasham/ciphersuites"
)

func TestClassification(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		classification ciphersuites.Classification
		want           string
	}{
		"returns recommended": {
			classification: ciphersuites.Recommended,
			want:           "recommended",
		},
		"returns secure": {
			classification: ciphersuites.Secure,
			want:           "secure",
		},
		"returns weak": {
			classification: ciphersuites.Weak,
			want:           "weak",
		},
		"returns insecure": {
			classification: ciphersuites.Insecure,
			want:           "insecure",
		},
		"returns unknown": {
			classification: ciphersuites.Unknown,
			want:           "unknown",
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.classification.String()
			if got != tt.want {
				t.Errorf("mismatch:\n  got:  %q\n  want: %q", got, tt.want)
			}
		})
	}
}

func TestGetClassification(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite string
		want        ciphersuites.Classification
	}{
		"returns recommended": {
			cipherSuite: "TLS_AES_128_CCM_SHA256",
			want:        ciphersuites.Recommended,
		},
		"returns secure": {
			cipherSuite: "TLS_AEGIS_128L_SHA256",
			want:        ciphersuites.Secure,
		},
		"returns weak": {
			cipherSuite: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
			want:        ciphersuites.Weak,
		},
		"returns insecure": {
			cipherSuite: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
			want:        ciphersuites.Insecure,
		},
		"returns unknown": {
			cipherSuite: "UNKNOWN_CIPHER_SUITE",
			want:        ciphersuites.Unknown,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := ciphersuites.GetClassification(tt.cipherSuite)
			if got != tt.want {
				t.Errorf("mismatch:\n  got:  %q\n  want: %q", got, tt.want)
			}
		})
	}
}
