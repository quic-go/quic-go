package http3

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorCodes(t *testing.T) {
	// We parse the error code file, extract all constants, and verify that
	// each of them has a string version. Go FTW!
	_, thisfile, _, ok := runtime.Caller(0)
	require.True(t, ok, "Failed to get current frame")

	filename := path.Join(path.Dir(thisfile), "error_codes.go")
	fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	require.NoError(t, err)

	constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
	require.Greater(t, len(constSpecs), 4) // at time of writing

	for _, c := range constSpecs {
		valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
		val, err := strconv.ParseInt(valString, 0, 64)
		require.NoError(t, err)
		require.NotEqual(t, "unknown error code", ErrCode(val).String())
	}

	// Test unknown error code
	require.Equal(t, "unknown error code: 0x1337", ErrCode(0x1337).String())
}
