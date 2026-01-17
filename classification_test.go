package ciphersuites_test

import (
	"testing"

	"github.com/tomasbasham/ciphersuites"
)

func TestClassification(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		classification ciphersuites.Classification
		expected       string
	}{
		"returns recommended": {
			classification: ciphersuites.Recommended,
			expected:       "recommended",
		},
		"returns secure": {
			classification: ciphersuites.Secure,
			expected:       "secure",
		},
		"returns weak": {
			classification: ciphersuites.Weak,
			expected:       "weak",
		},
		"returns insecure": {
			classification: ciphersuites.Insecure,
			expected:       "insecure",
		},
		"returns unknown": {
			classification: ciphersuites.Unknown,
			expected:       "unknown",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if classification := tt.classification.String(); classification != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, classification)
			}
		})
	}
}

func TestGetClassification(t *testing.T) {
	t.Parallel()

	var tests = map[string]struct {
		cipherSuite    string
		classification ciphersuites.Classification
	}{
		"returns recommended": {
			cipherSuite:    "TLS_AES_128_CCM_SHA256",
			classification: ciphersuites.Recommended,
		},
		"returns secure": {
			cipherSuite:    "TLS_AEGIS_128L_SHA256",
			classification: ciphersuites.Secure,
		},
		"returns weak": {
			cipherSuite:    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
			classification: ciphersuites.Weak,
		},
		"returns insecure": {
			cipherSuite:    "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
			classification: ciphersuites.Insecure,
		},
		"returns unknown": {
			cipherSuite:    "UNKNOWN_CIPHER_SUITE",
			classification: ciphersuites.Unknown,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if classification := ciphersuites.GetClassification(tt.cipherSuite); classification != tt.classification {
				t.Errorf("expected %q, got %q", tt.classification, classification)
			}
		})
	}
}
