// +build !quictrace

package quictrace

import "github.com/lucas-clemente/quic-go/internal/protocol"

// NewTracer returns a new Tracer that doesn't do anything.
func NewTracer() Tracer {
	return &nullTracer{}
}

type nullTracer struct{}

var _ Tracer = &nullTracer{}

func (t *nullTracer) Trace(protocol.ConnectionID, Event) {}
func (t *nullTracer) GetAllTraces() map[string][]byte    { return make(map[string][]byte) }
