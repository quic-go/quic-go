package qlog

import (
	"context"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

// RedactHeaders wraps a QUIC connection tracer to redact HTTP/3 header and trailer field values.
// redact receives names canonicalized by [http.CanonicalHeaderKey].
// Pseudoheaders are left unchanged.
func RedactHeaders(
	tracer func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace,
	redact func(name, value string) string,
) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	if tracer == nil || redact == nil {
		return tracer
	}
	return func(ctx context.Context, client bool, id quic.ConnectionID) qlogwriter.Trace {
		trace := tracer(ctx, client, id)
		if trace == nil {
			return nil
		}
		return &headerRedactingTrace{Trace: trace, redact: redact}
	}
}

type headerRedactingTrace struct {
	qlogwriter.Trace
	redact func(name, value string) string
}

var _ qlogwriter.Trace = &headerRedactingTrace{}

func (t *headerRedactingTrace) AddProducer() qlogwriter.Recorder {
	recorder := t.Trace.AddProducer()
	if recorder == nil {
		return nil
	}
	return &headerRedactingRecorder{Recorder: recorder, redact: t.redact}
}

type headerRedactingRecorder struct {
	qlogwriter.Recorder
	redact func(name, value string) string
}

var _ qlogwriter.Recorder = &headerRedactingRecorder{}

func (r *headerRedactingRecorder) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case FrameCreated:
		r.redactFrame(e.Frame)
	case FrameParsed:
		r.redactFrame(e.Frame)
	}
	r.Recorder.RecordEvent(event)
}

func (r *headerRedactingRecorder) redactFrame(frame Frame) {
	hf, ok := frame.Frame.(HeadersFrame)
	if !ok {
		return
	}
	for i, f := range hf.HeaderFields {
		// pseudoheaders are left unchanged
		if !strings.HasPrefix(f.Name, ":") {
			hf.HeaderFields[i].Value = r.redact(http.CanonicalHeaderKey(f.Name), f.Value)
		}
	}
}
