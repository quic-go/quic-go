package qlog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/francoispqt/gojay"
	"github.com/stretchr/testify/require"
)

type testEvent struct {
	message string
}

func (e testEvent) Name() string {
	return "transport:test_event"
}

func (e testEvent) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("message", e.message)
}

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

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
	fileSeq := NewFileSeq(&limitedWriter{WriteCloser: nopWriteCloser(buf), N: 250})
	writer := fileSeq.AddProducer()
	go fileSeq.Run()

	for i := range 1000 {
		writer.RecordEvent(time.Now(), testEvent{message: fmt.Sprintf("test message %d", i)})
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stdout)

	writer.Close()

	require.Contains(t, logBuf.String(), "writer full")
}
