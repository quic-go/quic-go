package qlog

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go/logging"

	"github.com/francoispqt/gojay"
)

const eventChanSize = 50

const recordSeparator = 0x1e

func writeRecordSeparator(w io.Writer) error {
	_, err := w.Write([]byte{recordSeparator})
	return err
}

// A Writer serializes to qlog.
type Writer struct {
	WriteCloser  io.WriteCloser
	VantagePoint string
	ODCID        *logging.ConnectionID

	referenceTime time.Time

	runOnce    sync.Once
	events     chan event
	encodeErr  error
	runStopped chan struct{}
}

func (w *Writer) init() {
	w.events = make(chan event, eventChanSize)
	w.runStopped = make(chan struct{})
	w.referenceTime = time.Now()
	go w.run()
}

func (w *Writer) RecordEvent(t time.Time, ev Event) {
	w.runOnce.Do(w.init)
	w.events <- event{
		RelativeTime: t.Sub(w.referenceTime),
		Event:        ev,
	}
}

func (w *Writer) run() {
	defer close(w.runStopped)

	buf := &bytes.Buffer{}
	enc := gojay.NewEncoder(buf)
	if err := writeRecordSeparator(buf); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if err := enc.Encode(&topLevel{trace: trace{
		VantagePoint: vantagePoint{Type: w.VantagePoint},
		CommonFields: commonFields{
			ODCID:         w.ODCID,
			GroupID:       w.ODCID,
			ReferenceTime: w.referenceTime,
		},
	}}); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if err := buf.WriteByte('\n'); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if _, err := w.WriteCloser.Write(buf.Bytes()); err != nil {
		w.encodeErr = err
	}
	enc = gojay.NewEncoder(w.WriteCloser)
	for ev := range w.events {
		if w.encodeErr != nil { // if encoding failed, just continue draining the event channel
			continue
		}
		if err := writeRecordSeparator(w.WriteCloser); err != nil {
			w.encodeErr = err
			continue
		}
		if err := enc.Encode(ev); err != nil {
			w.encodeErr = err
			continue
		}
		if _, err := w.WriteCloser.Write([]byte{'\n'}); err != nil {
			w.encodeErr = err
		}
	}
}

func (w *Writer) Close() {
	if err := w.close(); err != nil {
		log.Printf("exporting qlog failed: %s\n", err)
	}
}

func (w *Writer) close() error {
	w.runOnce.Do(w.init)
	close(w.events)
	<-w.runStopped
	if w.encodeErr != nil {
		return w.encodeErr
	}
	return w.WriteCloser.Close()
}
