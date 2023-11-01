package qerr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"
	"testing"
)

func TestErrorCodes(t *testing.T) {
	t.Run("Stringer", func(t *testing.T) {
		defer func() {
			if t.Failed() {
				t.Log("If this test breaks, you should run `go generate ./...`")
			}
		}()
		// We parse the error code file, extract all constants, and verify that
		// each of them has a string version. Go FTW!
		_, thisfile, _, ok := runtime.Caller(0)
		if !ok {
			panic("Failed to get current frame")
		}
		filename := path.Join(path.Dir(thisfile), "error_codes.go")
		fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Error(err)
		}
		constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
		if got, want := len(constSpecs), 16; got < want { // at time of writing
			t.Errorf("not enough constants: got: %d, want: >= %d", got, want)
		}
		for _, c := range constSpecs {
			valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
			val, err := strconv.ParseInt(valString, 0, 64)
			if err != nil {
				t.Error(err)
			}
			if s := TransportErrorCode(val).String(); s == "unknown error code" {
				t.Errorf("%d: %s", val, s)
			}
		}
	})

	t.Run("Unknown", func(t *testing.T) {
		got, want := TransportErrorCode(0x1337).String(), "unknown error code: 0x1337"
		if got != want {
			t.Errorf("bad fmt.Stringer: got: %q, want %q", got, want)
		}
	})

	t.Run("Crypto", func(t *testing.T) {
		want := func(i int) bool { return i >= 0x100 && i < 0x200 }
		for i := 0; i < 0x300; i++ {
			if got, want := TransportErrorCode(i).IsCryptoError(), want(i); got != want {
				t.Errorf("unexpected `IsCryptoError` return: got: %v, want: %v", got, want)
			}
		}
	})
}
