package ciphersuites

// CipherSuite represents the security attributes associated to a cipher suite.
type CipherSuite struct {
	ProtocolVersion     string
	EncryptionAlgorithm string
	HashAlgorithm       string
	Classification      Classification

	// Supported versions of the TLS protocol that can negotiate this cipher
	// suite.
	TLSVersions []string
}

// IsRecommended returns true if the cipher suite is secure and recommended for
// use.
func (a CipherSuite) IsRecommended() bool {
	return a.Classification == Recommended
}

// IsSecure returns true if the cipher suite is secure.
func (a CipherSuite) IsSecure() bool {
	return a.Classification == Secure
}

// IsWeak returns true if the cipher suite is weak.
func (a CipherSuite) IsWeak() bool {
	return a.Classification == Weak
}

// IsInsecure returns true if the cipher suite is insecure.
func (a CipherSuite) IsInsecure() bool {
	return a.Classification == Insecure
}

// GetCipherSuite retrieves the [CipherSuite] by its name.
func GetCipherSuite(cipherSuite string) (CipherSuite, bool) {
	if cs, ok := RecommendedCipherSuites[cipherSuite]; ok {
		return cs, true
	}

	if cs, ok := SecureCipherSuites[cipherSuite]; ok {
		return cs, true
	}

	if cs, ok := WeakCipherSuites[cipherSuite]; ok {
		return cs, true
	}

	if cs, ok := InsecureCipherSuites[cipherSuite]; ok {
		return cs, true
	}

	return CipherSuite{}, false
}
