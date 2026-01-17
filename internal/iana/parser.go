package iana

import (
	"strings"

	"github.com/tomasbasham/ciphersuites/internal/domain"
)

// Parser converts IANA CSV records into domain models
type Parser struct {
	classifier *SecurityClassifier
}

// NewParser creates a new IANA record parser
func NewParser() *Parser {
	return &Parser{
		classifier: NewSecurityClassifier(),
	}
}

// ParseRecord converts a CSV record into a CipherSuite
func (p *Parser) ParseRecord(record []string) (domain.CipherSuite, bool) {
	if len(record) < 6 {
		return domain.CipherSuite{}, false
	}

	value := record[0]
	description := record[1]
	dtlsOK := record[2]
	recommended := record[3]

	// Skip reserved, unassigned, and ranges
	if p.shouldSkip(description, value) {
		return domain.CipherSuite{}, false
	}

	security := p.classifier.Classify(recommended, dtlsOK, description)
	protocol, encryption, hash := p.parseComponents(description)
	versions := p.determineTLSVersions(description, value)

	return domain.CipherSuite{
		Name:        description,
		Protocol:    protocol,
		Encryption:  encryption,
		Hash:        hash,
		Security:    security,
		TLSVersions: versions,
	}, true
}

func (p *Parser) shouldSkip(description, value string) bool {
	return strings.Contains(description, "Reserved") ||
		strings.Contains(description, "Unassigned") ||
		strings.Contains(description, "avoid conflicts") ||
		strings.Contains(value, "-") ||
		!strings.HasPrefix(description, "TLS_")
}

func (p *Parser) parseComponents(name string) (protocol, encryption, hash string) {
	parts := strings.TrimPrefix(name, "TLS_")

	// Determine protocol
	protocol = "TLS"
	if strings.Contains(name, "EXPORT") {
		protocol = "TLS EXPORT"
	}

	// Extract encryption algorithm (after WITH)
	if idx := strings.Index(parts, "_WITH_"); idx != -1 {
		remainder := parts[idx+6:]

		// Find the hash at the end
		hashPrefixes := []string{"_SHA512", "_SHA384", "_SHA256", "_SHA", "_MD5", "_SM3"}
		for _, prefix := range hashPrefixes {
			if idx := strings.LastIndex(remainder, prefix); idx != -1 {
				hash = strings.TrimPrefix(remainder[idx+1:], "_")
				encryption = strings.ReplaceAll(remainder[:idx], "_", " ")
				return
			}
		}

		encryption = strings.ReplaceAll(remainder, "_", " ")
	} else {
		// TLS 1.3 format (no WITH)
		parts := strings.Split(parts, "_")
		if len(parts) >= 2 {
			hash = parts[len(parts)-1]
			encryption = strings.Join(parts[:len(parts)-1], " ")
		}
	}

	return
}

func (p *Parser) determineTLSVersions(name, value string) []string {
	// TLS 1.3 cipher suites
	if strings.HasPrefix(value, "0x13,") {
		return []string{"TLS1.3"}
	}

	// EXPORT ciphers are TLS 1.0-1.2 only
	if strings.Contains(name, "EXPORT") {
		return []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
	}

	// SHA256/SHA384 variants require at least TLS 1.2
	if strings.Contains(name, "SHA256") || strings.Contains(name, "SHA384") {
		return []string{"TLS1.2", "TLS1.3"}
	}

	// GCM mode requires TLS 1.2+
	if strings.Contains(name, "GCM") {
		return []string{"TLS1.2", "TLS1.3"}
	}

	// Default: all versions
	return []string{"TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
}
