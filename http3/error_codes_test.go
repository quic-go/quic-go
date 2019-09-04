package http3

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("error codes", func() {
	It("has a string representation for every error code", func() {
		// We parse the error code file, extract all constants, and verify that
		// each of them has a string version. Go FTW!
		_, thisfile, _, ok := runtime.Caller(0)
		if !ok {
			panic("Failed to get current frame")
		}
		filename := path.Join(path.Dir(thisfile), "error_codes.go")
		fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		Expect(err).NotTo(HaveOccurred())
		constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
		Expect(len(constSpecs)).To(BeNumerically(">", 4)) // at time of writing
		for _, c := range constSpecs {
			valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
			val, err := strconv.ParseInt(valString, 0, 64)
			Expect(err).NotTo(HaveOccurred())
			Expect(errorCode(val).String()).ToNot(Equal("unknown error code"))
		}
	})

	It("has a string representation for unknown error codes", func() {
		Expect(errorCode(0x1337).String()).To(Equal("unknown error code: 0x1337"))
	})
})
