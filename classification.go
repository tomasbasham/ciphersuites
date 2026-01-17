package ciphersuites

// Classification specifies the security class a cipher suite falls under.
type Classification byte

const (
	// Unknown represents the security classification of an unknown cipher suite.
	Unknown Classification = iota
	// Recommended represents the security classification of a secure and
	// recommended cipher suite.
	Recommended
	// Secure represents the security classification of a secure cipher suite.
	Secure
	// Weak represents the securty classification of a weak cipher suite.
	Weak
	// Insecure represents the security classification of an insecure cipher
	// suite.
	Insecure
)

func (c Classification) String() string {
	switch c {
	case Recommended:
		return "recommended"
	case Secure:
		return "secure"
	case Weak:
		return "weak"
	case Insecure:
		return "insecure"
	default:
		return "unknown"
	}
}

// GetClassification returns the security classification of a given cipher
// suite. If the cipher suite cannot be found then its classification is
// unknown.
func GetClassification(cipherSuite string) Classification {
	if cs, ok := RecommendedCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	if cs, ok := SecureCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	if cs, ok := WeakCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	if cs, ok := InsecureCipherSuites[cipherSuite]; ok {
		return cs.Classification
	}

	return Unknown
}
