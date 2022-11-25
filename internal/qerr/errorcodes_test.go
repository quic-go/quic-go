package qerr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("error codes", func() {
	// If this test breaks, you should run `go generate ./...`
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
			Expect(TransportErrorCode(val).String()).ToNot(Equal("unknown error code"))
		}
	})

	It("has a string representation for unknown error codes", func() {
		Expect(TransportErrorCode(0x1337).String()).To(Equal("unknown error code: 0x1337"))
	})

	It("says if an error is a crypto error", func() {
		for i := 0; i < 0x100; i++ {
			Expect(TransportErrorCode(i).IsCryptoError()).To(BeFalse())
		}
		for i := 0x100; i < 0x200; i++ {
			Expect(TransportErrorCode(i).IsCryptoError()).To(BeTrue())
		}
		for i := 0x200; i < 0x300; i++ {
			Expect(TransportErrorCode(i).IsCryptoError()).To(BeFalse())
		}
	})
})
