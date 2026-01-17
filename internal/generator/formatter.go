package generator

import (
	"bytes"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
)

type Formatter struct{}

func NewFormatter() *Formatter {
	return &Formatter{}
}

func (f *Formatter) Format(code []byte) ([]byte, error) {
	// Create a FileSet for node. Since the node does not come
	// from a real source file, fset will be empty.
	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, "", string(code), parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated code: %w", err)
	}

	var buf bytes.Buffer
	err = format.Node(&buf, fset, file)
	if err != nil {
		return nil, fmt.Errorf("failed to format generated code: %w", err)
	}

	return buf.Bytes(), nil
}
