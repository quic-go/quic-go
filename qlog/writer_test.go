package qlog

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

type limitedWriter struct {
	io.WriteCloser
	N       int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.N {
		return 0, errors.New("writer full")
	}
	n, err := w.WriteCloser.Write(p)
	w.written += n
	return n, err
}

func TestWritingStopping(t *testing.T) {
	buf := &bytes.Buffer{}
	t.Run("stops writing when encountering an error", func(t *testing.T) {
		tracer := NewConnectionTracer(
			&limitedWriter{WriteCloser: nopWriteCloser(buf), N: 250},
			protocol.PerspectiveServer,
			protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		)

		for i := uint32(0); i < 1000; i++ {
			tracer.UpdatedPTOCount(i)
		}

		// Capture log output
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)
		defer log.SetOutput(os.Stdout)

		tracer.Close()

		require.Contains(t, logBuf.String(), "writer full")
	})
}
