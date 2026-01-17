// Generator generates Go code for TLS cipher suites.
//
// Usage:
//
//	go run github.com/tomasbasham/ciphersuites/cmd/generate [flags]
//
// Flags:
//
//	-output string
//	    Output file path (default "ciphersuites.gen.go")
//
//	-package string
//	    Package name for generated code (default "ciphersuites")
//
// The generated codes will be written to the given output file and formatted
// using gofmt.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tomasbasham/ciphersuites/internal/generator"
	"github.com/tomasbasham/ciphersuites/internal/iana"
)

const ianaURL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"

func main() {
	var (
		outputFile  string
		packageName string
	)

	flag.StringVar(&outputFile, "output", "ciphersuites.gen.go", "Output file path")
	flag.StringVar(&packageName, "package", "ciphersuites", "Package name for generated code")
	flag.Parse()

	if err := run(outputFile, packageName); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(outputFile, packageName string) error {
	fmt.Println("Fetching IANA TLS Cipher Suite Registry...")
	fetcher := iana.NewFetcher()
	suites, err := fetcher.FetchCipherSuites(ianaURL)
	if err != nil {
		return fmt.Errorf("failed to fetch cipher suites: %w", err)
	}

	fmt.Printf("Fetched %d cipher suites\n", len(suites))

	// Group by security level
	grouped := generator.GroupBySecurityLevel(suites)

	// Generate code
	fmt.Println("Generating Go code...")
	gen := generator.NewCodeGenerator(packageName, ianaURL)
	code, err := gen.Generate(grouped)
	if err != nil {
		return fmt.Errorf("failed to generate code: %w", err)
	}

	// Format code
	fmt.Println("Formatting generated code...")
	formatter := generator.NewFormatter()
	code, err = formatter.Format(code)
	if err != nil {
		return fmt.Errorf("failed to format code: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputFile, code, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Successfully generated %s\n", outputFile)
	fmt.Printf("Statistics:\n")
	for level, suites := range grouped {
		fmt.Printf("  %s: %d cipher suites\n", level, len(suites))
	}

	return nil
}
