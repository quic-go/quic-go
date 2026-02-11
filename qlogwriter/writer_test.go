package qlogwriter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

type testEvent struct {
	message string
}

func (e testEvent) Name() string {
	return "transport:test_event"
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

type blockingWriter struct {
	bytes.Buffer
	block   bool
	unblock chan struct{}
}

func (w *blockingWriter) Write(b []byte) (int, error) {
	if w.block {
		<-w.unblock
	}
	return w.Buffer.Write(b)
}

// TestRecordCloseRace triggers a race between record and Close.
func TestRecordCloseRace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := &blockingWriter{unblock: make(chan struct{})}
		trace := NewFileSeq(nopWriteCloser(w))
		go trace.Run()
		synctest.Wait() // Run is blocked waiting for events

		producer := trace.AddProducer()
		require.NotNil(t, producer)

		w.block = true
		const numEvents = eventChanSize + 1
		for i := range numEvents {
			producer.RecordEvent(testEvent{message: fmt.Sprintf("event %d", i)})
		}

		go producer.RecordEvent(testEvent{message: "last event"})
		synctest.Wait() // goroutine is blocked on full channel

		close(w.unblock) // let Run() finish
		producer.Close()

		for i := range numEvents {
			require.Contains(t, w.String(), fmt.Sprintf(`"message":"event %d"`, i))
		}
		require.Contains(t, w.String(), `"message":"last event"`)
	})
}
