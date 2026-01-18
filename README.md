# ciphersuites [![test](https://github.com/tomasbasham/ciphersuites/actions/workflows/test.yaml/badge.svg?event=push)](https://github.com/tomasbasham/ciphersuites/actions/workflows/test.yaml)

A Go module providing TLS cipher suite classifications based on current security
standards. It categorises cipher suites into four security levels - recommended,
secure, weak, and insecure - enabling you to make informed decisions about TLS
configuration and security policy enforcement.

The classification data is generated from the official IANA TLS parameters
registry, ensuring up-to-date cipher suite information across TLS 1.0 through
1.3.

## Prerequisites

You will need the following things properly installed on your computer:

- [Go](https://golang.org/): any one of the **three latest major**
  [releases](https://golang.org/doc/devel/release.html)

## Installation

With [Go module](https://go.dev/wiki/Modules) support (Go 1.11+), simply add the
following import

```go
import "github.com/tomasbasham/ciphersuites"
```

to your code, and then `go [build|run|test]` will automatically fetch the
necessary dependencies.

Otherwise, to install the `ciphersuites` package, run the following command:

```bash
go get -u github.com/tomasbasham/ciphersuites
```

## Usage

To use this module, import it into your Go application and query cipher suite
information using either the classification maps or helper functions.

```go
package main

import (
    "fmt"

    "github.com/tomasbasham/ciphersuites"
)

func main() {
    classification := ciphersuites.GetClassification("TLS_AES_256_GCM_SHA384")
    fmt.Printf("Classification: %s\n", classification)

    // Retrieve full cipher suite details.
    cs, found := ciphersuites.GetCipherSuite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    if !found {
        fmt.Println("Cipher suite not found")
        return
    }

    fmt.Printf("Protocol: %s\n", cs.ProtocolVersion)
    fmt.Printf("Encryption: %s\n", cs.EncryptionAlgorithm)
    fmt.Printf("Hash: %s\n", cs.HashAlgorithm)
    fmt.Printf("Classification: %s\n", cs.Classification)
    fmt.Printf("TLS Versions: %v\n", cs.TLSVersions)

    if cs.IsRecommended() {
        fmt.Println("This cipher suite is recommended")
    }
}
```

### Print Recommended Cipher Suites

To list all recommended cipher suites along with their encryption algorithms:

```go
for name, cs := range ciphersuites.RecommendedCipherSuites {
    fmt.Printf("%s: %s\n", name, cs.EncryptionAlgorithm)
}
```

## Security Classifications

The module categorises cipher suites into four levels:

- **Recommended:** Cipher suites that are both secure and recommended for
  current use
- **Secure:** Cipher suites that are secure but may not be the preferred choice
- **Weak:** Cipher suites with known weaknesses that should be avoided
- **Insecure:** Cipher suites that are cryptographically broken and must not be
  used

## License

This project is licensed under the [MIT License](LICENSE).
