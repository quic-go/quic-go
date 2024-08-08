package qlog

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/francoispqt/gojay"
)

const eventChanSize = 50

const recordSeparator = 0x1e

func writeRecordSeparator(w io.Writer) error {
	_, err := w.Write([]byte{recordSeparator})
	return err
}

type writer struct {
	w io.WriteCloser

	referenceTime time.Time
	tr            *trace

	events     chan event
	encodeErr  error
	runStopped chan struct{}
}

func newWriter(w io.WriteCloser, tr *trace) *writer {
	return &writer{
		w:             w,
		tr:            tr,
		referenceTime: tr.CommonFields.ReferenceTime,
		runStopped:    make(chan struct{}),
		events:        make(chan event, eventChanSize),
	}
}

func (w *writer) RecordEvent(eventTime time.Time, details eventDetails) {
	w.events <- event{
		RelativeTime: eventTime.Sub(w.referenceTime),
		eventDetails: details,
	}
}

func (w *writer) Run() {
	defer close(w.runStopped)
	buf := &bytes.Buffer{}
	enc := gojay.NewEncoder(buf)
	if err := writeRecordSeparator(buf); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if err := enc.Encode(&topLevel{trace: *w.tr}); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if err := buf.WriteByte('\n'); err != nil {
		panic(fmt.Sprintf("qlog encoding into a bytes.Buffer failed: %s", err))
	}
	if _, err := w.w.Write(buf.Bytes()); err != nil {
		w.encodeErr = err
	}
	enc = gojay.NewEncoder(w.w)
	for ev := range w.events {
		if w.encodeErr != nil { // if encoding failed, just continue draining the event channel
			continue
		}
		if err := writeRecordSeparator(w.w); err != nil {
			w.encodeErr = err
			continue
		}
		if err := enc.Encode(ev); err != nil {
			w.encodeErr = err
			continue
		}
		if _, err := w.w.Write([]byte{'\n'}); err != nil {
			w.encodeErr = err
		}
	}
}

func (w *writer) Close() {
	if err := w.close(); err != nil {
		log.Printf("exporting qlog failed: %s\n", err)
	}
}

func (w *writer) close() error {
	close(w.events)
	<-w.runStopped
	if w.encodeErr != nil {
		return w.encodeErr
	}
	return w.w.Close()
}
