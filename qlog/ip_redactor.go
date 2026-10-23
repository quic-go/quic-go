package qlog

import (
	"context"
	"net/netip"

	"github.com/quic-go/quic-go/qlogwriter"
)

// RedactIPs wraps a QUIC connection tracer to redact endpoint and preferred addresses.
// redact returns the replacement and whether to apply it.
func RedactIPs(
	tracer func(context.Context, bool, ConnectionID) qlogwriter.Trace,
	redact func(addr netip.AddrPort, isLocal bool) (string, bool),
) func(context.Context, bool, ConnectionID) qlogwriter.Trace {
	if tracer == nil || redact == nil {
		return tracer
	}
	return func(ctx context.Context, client bool, id ConnectionID) qlogwriter.Trace {
		trace := tracer(ctx, client, id)
		if trace == nil {
			return nil
		}
		return &ipRedactingTrace{Trace: trace, redact: redact}
	}
}

type ipRedactingTrace struct {
	qlogwriter.Trace
	redact func(netip.AddrPort, bool) (string, bool)
}

var _ qlogwriter.Trace = &ipRedactingTrace{}

func (t *ipRedactingTrace) AddProducer() qlogwriter.Recorder {
	recorder := t.Trace.AddProducer()
	if recorder == nil {
		return nil
	}
	return &ipRedactingRecorder{Recorder: recorder, redact: t.redact}
}

type ipRedactingRecorder struct {
	qlogwriter.Recorder
	redact func(netip.AddrPort, bool) (string, bool)
}

var _ qlogwriter.Recorder = &ipRedactingRecorder{}

func (r *ipRedactingRecorder) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case StartedConnection:
		if e.Local.IPv4.IsValid() {
			if v, ok := r.redact(e.Local.IPv4, true); ok {
				e.RedactedLocal = &v
			}
		} else if e.Local.IPv6.IsValid() {
			if v, ok := r.redact(e.Local.IPv6, true); ok {
				e.RedactedLocal = &v
			}
		}
		if e.Remote.IPv4.IsValid() {
			if v, ok := r.redact(e.Remote.IPv4, false); ok {
				e.RedactedRemote = &v
			}
		} else if e.Remote.IPv6.IsValid() {
			if v, ok := r.redact(e.Remote.IPv6, false); ok {
				e.RedactedRemote = &v
			}
		}
		event = e
	case ParametersSet:
		if e.PreferredAddress != nil {
			isLocal := e.Initiator == InitiatorLocal
			addr := *e.PreferredAddress
			if addr.IPv4.IsValid() {
				if v, ok := r.redact(addr.IPv4, isLocal); ok {
					addr.RedactedIPv4 = &v
				}
			}
			if addr.IPv6.IsValid() {
				if v, ok := r.redact(addr.IPv6, isLocal); ok {
					addr.RedactedIPv6 = &v
				}
			}
			e.PreferredAddress = &addr
			event = e
		}
	}
	r.Recorder.RecordEvent(event)
}
