package qerr

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

func TestTransportErrorCodeStringer(t *testing.T) {
	_, thisfile, _, ok := runtime.Caller(0)
	require.True(t, ok, "Failed to get current frame")

	filename := path.Join(path.Dir(thisfile), "error_codes.go")
	fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	require.NoError(t, err)

	constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
	require.Greater(t, len(constSpecs), 4, "Expected more than 4 constants")

	for _, c := range constSpecs {
		valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
		val, err := strconv.ParseInt(valString, 0, 64)
		require.NoError(t, err)
		require.NotEqual(t, "unknown error code", TransportErrorCode(val).String())
	}

	// test that there's a string representation for unknown error codes
	require.Equal(t, "unknown error code: 0x1337", TransportErrorCode(0x1337).String())
}

func TestIsCryptoError(t *testing.T) {
	for i := 0; i < 0x100; i++ {
		require.False(t, TransportErrorCode(i).IsCryptoError())
	}
	for i := 0x100; i < 0x200; i++ {
		require.True(t, TransportErrorCode(i).IsCryptoError())
	}
	for i := 0x200; i < 0x300; i++ {
		require.False(t, TransportErrorCode(i).IsCryptoError())
	}
}
