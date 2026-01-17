//go:generate go run cmd/generator/main.go
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

func (a CipherSuite) IsRecommended() bool {
	return a.Classification == Recommended
}

func (a CipherSuite) IsSecure() bool {
	return a.Classification == Secure
}

func (a CipherSuite) IsWeak() bool {
	return a.Classification == Weak
}

func (a CipherSuite) IsInsecure() bool {
	return a.Classification == Insecure
}

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
