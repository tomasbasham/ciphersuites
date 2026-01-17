package domain

// CipherSuite represents a TLS cipher suite.
type CipherSuite struct {
	Name        string
	Protocol    string
	Encryption  string
	Hash        string
	Security    SecurityLevel
	TLSVersions []string
}

// SecurityLevel represents the security classification of a cipher suite
type SecurityLevel string

const (
	Recommended SecurityLevel = "Recommended"
	Secure      SecurityLevel = "Secure"
	Weak        SecurityLevel = "Weak"
	Insecure    SecurityLevel = "Insecure"
)
