package helper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func createTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fuzzing-helper")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestWriteCorpusFile(t *testing.T) {
	const data = "lorem ipsum"
	const expectedShaSum = "bfb7759a67daeb65410490b4d98bb9da7d1ea2ce"

	dir := createTempDir(t)
	require.NoError(t, WriteCorpusFile(dir, []byte(data)))

	path := filepath.Join(dir, expectedShaSum)
	require.FileExists(t, path)

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, string(b))
}

func TestWriteCorpusFileWithPrefix(t *testing.T) {
	const data = "lorem ipsum"
	const expectedShaSum = "523f5cab80fab0c7889dbf50dd310ab8c8879f9c"
	const prefixLen = 7

	dir := createTempDir(t)
	require.NoError(t, WriteCorpusFileWithPrefix(dir, []byte(data), prefixLen))

	path := filepath.Join(dir, expectedShaSum)
	require.FileExists(t, path)

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, make([]byte, prefixLen), b[:prefixLen])
	require.Equal(t, data, string(b[prefixLen:]))
}

func TestCreateDirectoryIfNotExists(t *testing.T) {
	dir := createTempDir(t)
	subdir := filepath.Join(dir, "corpus")
	require.NoDirExists(t, subdir)

	require.NoError(t, WriteCorpusFile(subdir, []byte("lorem ipsum")))
	require.DirExists(t, subdir)
}

func TestNthBit(t *testing.T) {
	const val = 0b10010001

	require.True(t, NthBit(val, 0))
	require.False(t, NthBit(val, 1))
	require.False(t, NthBit(val, 2))
	require.False(t, NthBit(val, 3))
	require.True(t, NthBit(val, 4))
	require.False(t, NthBit(val, 5))
	require.False(t, NthBit(val, 6))
	require.True(t, NthBit(val, 7))
}
