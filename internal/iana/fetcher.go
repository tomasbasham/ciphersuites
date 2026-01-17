package iana

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tomasbasham/ciphersuites/internal/domain"
)

// Fetcher retrieves cipher suite data from IANA
type Fetcher struct {
	client *http.Client
	parser *Parser
}

// NewFetcher creates a new IANA fetcher
func NewFetcher() *Fetcher {
	return &Fetcher{
		client: &http.Client{Timeout: 30 * time.Second},
		parser: NewParser(),
	}
}

// FetchCipherSuites retrieves and parses cipher suites from the IANA registry
func (f *Fetcher) FetchCipherSuites(url string) ([]domain.CipherSuite, error) {
	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)

	// Skip header
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	var suites []domain.CipherSuite
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV record: %w", err)
		}

		if suite, ok := f.parser.ParseRecord(record); ok {
			suites = append(suites, suite)
		}
	}

	return suites, nil
}
