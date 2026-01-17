package iana

import (
	"strings"

	"github.com/tomasbasham/ciphersuites/internal/domain"
)

// SecurityClassifier determines the security level of cipher suites
type SecurityClassifier struct {
	insecureAlgorithms []string
	weakAlgorithms     []string
}

// NewSecurityClassifier creates a new security classifier
func NewSecurityClassifier() *SecurityClassifier {
	return &SecurityClassifier{
		insecureAlgorithms: []string{
			"NULL", "EXPORT", "DES40", "DES_CBC", "RC4", "RC2",
			"anon", "MD5",
		},
		weakAlgorithms: []string{
			"3DES", "CBC", "IDEA", "SEED",
		},
	}
}

// Classify determines the security level based on IANA's recommendation
func (c *SecurityClassifier) Classify(recommended, dtlsOK, name string) domain.SecurityLevel {
	// IANA uses: Y (Yes/Recommended), N (Not recommended), D (Discouraged)
	switch recommended {
	case "Y":
		return domain.Recommended
	case "D":
		return domain.Insecure
	case "N":
		if c.containsInsecureAlgorithm(name) {
			return domain.Insecure
		}
		if c.containsWeakAlgorithm(name) {
			return domain.Weak
		}
		return domain.Secure
	default:
		return domain.Weak
	}
}

func (c *SecurityClassifier) containsInsecureAlgorithm(name string) bool {
	nameUpper := strings.ToUpper(name)
	for _, alg := range c.insecureAlgorithms {
		if strings.Contains(nameUpper, alg) {
			return true
		}
	}
	return false
}

func (c *SecurityClassifier) containsWeakAlgorithm(name string) bool {
	// GCM and CCM modes are secure even though they contain "C"
	if strings.Contains(name, "GCM") || strings.Contains(name, "CCM") {
		return false
	}

	nameUpper := strings.ToUpper(name)
	for _, alg := range c.weakAlgorithms {
		if strings.Contains(nameUpper, alg) {
			return true
		}
	}
	return false
}
