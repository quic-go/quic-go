package qlogwriter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

type testEvent struct {
	message string
}

func (e testEvent) Name() string {
	return "quic:test_event"
}

func (e testEvent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("message"))
	h.WriteToken(jsontext.String(e.message))
	h.WriteToken(jsontext.EndObject)
	return h.err
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
		writer.RecordEvent(testEvent{message: fmt.Sprintf("test message %d", i)})
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stdout)

	writer.Close()

	require.Contains(t, logBuf.String(), "writer full")

	// events after closing are ignored
	logBuf.Reset()
	writer.RecordEvent(testEvent{message: "foobar"})
	require.Empty(t, logBuf.String())
}
