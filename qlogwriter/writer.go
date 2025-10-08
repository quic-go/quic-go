package qlogwriter

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// Trace represents a qlog trace that can have multiple event producers.
// Each producer can record events to the trace independently.
// When the last producer is closed, the underlying trace is closed as well.
type Trace interface {
	// AddProducer creates a new Recorder for this trace.
	// Each Recorder can record events independently.
	AddProducer() Recorder
}

// Recorder is used to record events to a qlog trace.
// It is safe for concurrent use by multiple goroutines.
type Recorder interface {
	// RecordEvent records a single Event to the trace.
	RecordEvent(Event)
	// Close signals that this producer is done recording events.
	// When all producers are closed, the underlying trace is closed.
	io.Closer
}

const eventChanSize = 50

var recordSeparator = []byte{0x1e}

// FileSeq represents a qlog trace using the JSON-SEQ format,
// https://www.ietf.org/archive/id/draft-ietf-quic-qlog-main-schema-12.html#section-5
// qlog event producers can be created by calling AddProducer.
// The underlying io.WriteCloser is closed when the last producer is removed.
type FileSeq struct {
	w             io.WriteCloser
	enc           *jsontext.Encoder
	referenceTime time.Time

	runStopped chan struct{}
	encodeErr  error
	events     chan event

	mx        sync.Mutex
	producers int
	closed    bool
}

var _ Trace = &FileSeq{}

// NewFileSeq creates a new JSON-SEQ qlog trace to log transport events.
func NewFileSeq(w io.WriteCloser) *FileSeq {
	return newFileSeq(w, "transport", nil)
}

// NewConnectionFileSeq creates a new qlog trace to log connection events.
func NewConnectionFileSeq(w io.WriteCloser, isClient bool, odcid ConnectionID) *FileSeq {
	pers := "server"
	if isClient {
		pers = "client"
	}
	return newFileSeq(w, pers, &odcid)
}

func newFileSeq(w io.WriteCloser, pers string, odcid *ConnectionID) *FileSeq {
	now := time.Now()
	buf := &bytes.Buffer{}
	enc := jsontext.NewEncoder(buf)
	if _, err := buf.Write(recordSeparator); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if err := (&traceHeader{
		VantagePointType: pers,
		GroupID:          odcid,
		ReferenceTime:    now,
	}).Encode(enc); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	_, encodeErr := w.Write(buf.Bytes())

	return &FileSeq{
		w:             w,
		referenceTime: now,
		enc:           jsontext.NewEncoder(w),
		runStopped:    make(chan struct{}),
		encodeErr:     encodeErr,
		events:        make(chan event, eventChanSize),
	}
}

func (t *FileSeq) AddProducer() Recorder {
	t.mx.Lock()
	defer t.mx.Unlock()
	if t.closed {
		return nil
	}

	t.producers++

	return &Writer{t: t}
}

func (t *FileSeq) record(eventTime time.Time, details Event) {
	t.mx.Lock()

	if t.closed {
		t.mx.Unlock()
		return
	}
	t.mx.Unlock()

	t.events <- event{
		RelativeTime: eventTime.Sub(t.referenceTime),
		Event:        details,
	}
}

func (t *FileSeq) Run() {
	defer close(t.runStopped)

	enc := jsontext.NewEncoder(t.w)
	for ev := range t.events {
		if t.encodeErr != nil { // if encoding failed, just continue draining the event channel
			continue
		}
		if _, err := t.w.Write(recordSeparator); err != nil {
			t.encodeErr = err
			continue
		}
		if err := ev.Encode(enc); err != nil {
			t.encodeErr = err
			continue
		}
	}
}

func (t *FileSeq) removeProducer() {
	t.mx.Lock()
	defer t.mx.Unlock()

	if t.closed {
		return
	}
	t.producers--
	if t.producers == 0 {
		t.closed = true
		t.close()
		t.w.Close()
	}
}

func (t *FileSeq) close() {
	close(t.events)
	<-t.runStopped
	if t.encodeErr != nil {
		log.Printf("exporting qlog failed: %s\n", t.encodeErr)
		return
	}
}

type Writer struct {
	t *FileSeq
}

func (w *Writer) Close() error {
	w.t.removeProducer()
	return nil
}

func (w *Writer) RecordEvent(ev Event) {
	w.t.record(time.Now(), ev)
}
