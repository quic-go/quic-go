package qlog

import (
	"io"

	"github.com/francoispqt/gojay"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// A Tracer records events to be exported to a qlog.
type Tracer interface {
	Export() error
}

type tracer struct {
	w           io.WriteCloser
	odcid       protocol.ConnectionID
	perspective protocol.Perspective

	events []event
}

var _ Tracer = &tracer{}

// NewTracer creates a new tracer to record a qlog.
func NewTracer(w io.WriteCloser, p protocol.Perspective, odcid protocol.ConnectionID) Tracer {
	return &tracer{
		w:           w,
		perspective: p,
		odcid:       odcid,
	}
}

// Export writes a qlog.
func (t *tracer) Export() error {
	enc := gojay.NewEncoder(t.w)
	tl := &topLevel{
		traces: traces{
			{
				VantagePoint: vantagePoint{Type: t.perspective},
				CommonFields: commonFields{ODCID: connectionID(t.odcid), GroupID: connectionID(t.odcid)},
				EventFields:  eventFields[:],
				Events:       t.events,
			},
		}}
	if err := enc.Encode(tl); err != nil {
		return err
	}
	return t.w.Close()
}
