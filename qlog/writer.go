package qlog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog/jsontext"
)

const eventChanSize = 50

var recordSeparator = []byte{0x1e}

// Trace represents a qlog trace.
// qlog event producers can be created by calling AddProducer.
// The underlying io.WriteCloser is closed when the last producer is removed.
type Trace struct {
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

func NewTrace(w io.WriteCloser) *Trace {
	return newTrace(w, "transport", nil)
}

// NewConnectionTrace creates a new qlog trace to log connection events..
func NewConnectionTrace(w io.WriteCloser, pers logging.Perspective, odcid logging.ConnectionID) *Trace {
	return newTrace(w, pers.String(), &odcid)
}

func newTrace(w io.WriteCloser, pers string, odcid *logging.ConnectionID) *Trace {
	now := time.Now()
	tr := &trace{
		VantagePoint: vantagePoint{Type: pers},
		CommonFields: commonFields{
			ODCID:         odcid,
			GroupID:       odcid,
			ReferenceTime: now,
		},
	}
	buf := &bytes.Buffer{}
	enc := jsontext.NewEncoder(buf)
	if _, err := buf.Write(recordSeparator); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if err := (&topLevel{trace: *tr}).Encode(enc); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	_, encodeErr := w.Write(buf.Bytes())

	return &Trace{
		w:             w,
		referenceTime: now,
		enc:           jsontext.NewEncoder(w),
		runStopped:    make(chan struct{}),
		encodeErr:     encodeErr,
		events:        make(chan event, eventChanSize),
	}
}

func (t *Trace) AddProducer() *Writer {
	t.mx.Lock()
	defer t.mx.Unlock()
	if t.closed {
		return nil
	}

	t.producers++

	return &Writer{
		t: t,
	}
}

func (t *Trace) record(eventTime time.Time, details eventDetails) error {
	t.mx.Lock()

	if t.closed {
		t.mx.Unlock()
		return errors.New("trace closed")
	}
	t.mx.Unlock()

	t.events <- event{
		RelativeTime: eventTime.Sub(t.referenceTime),
		eventDetails: details,
	}
	return nil
}

func (t *Trace) Run() {
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

func (t *Trace) removeProducer() {
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

func (t *Trace) close() {
	close(t.events)
	<-t.runStopped
	defer t.w.Close()
	if t.encodeErr != nil {
		log.Printf("exporting qlog failed: %s\n", t.encodeErr)
		return
	}
}

type Writer struct {
	t *Trace
}

func (w *Writer) Close() error {
	w.t.removeProducer()
	return nil
}

func (w *Writer) RecordEvent(time time.Time, details eventDetails) {
	err := w.t.record(time, details)
	_ = err
}
