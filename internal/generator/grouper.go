package generator

import (
	"sort"

	"github.com/tomasbasham/ciphersuites/internal/domain"
)

// GroupBySecurityLevel organises cipher suites by their security classification
func GroupBySecurityLevel(suites []domain.CipherSuite) map[domain.SecurityLevel][]domain.CipherSuite {
	grouped := make(map[domain.SecurityLevel][]domain.CipherSuite)

	for _, suite := range suites {
		grouped[suite.Security] = append(grouped[suite.Security], suite)
	}

	// Sort each group by name for consistent output
	for level := range grouped {
		sort.Slice(grouped[level], func(i, j int) bool {
			return grouped[level][i].Name < grouped[level][j].Name
		})
	}

	return grouped
}
