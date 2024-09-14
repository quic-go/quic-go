package utils

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestBufferedWriteCloserFlushBeforeClosing(t *testing.T) {
	buf := &bytes.Buffer{}

	w := bufio.NewWriter(buf)
	wc := NewBufferedWriteCloser(w, &nopCloser{})
	_, err := wc.Write([]byte("foobar"))
	require.NoError(t, err)
	require.Zero(t, buf.Len())
	require.NoError(t, wc.Close())
	require.Equal(t, "foobar", buf.String())
}
