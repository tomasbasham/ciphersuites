package main

import (
	"fmt"

	"github.com/tomasbasham/ciphersuites"
)

func main() {
	cipherSuite := "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
	classification := ciphersuites.GetClassification(cipherSuite)

	fmt.Println(classification)
}
