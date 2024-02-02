package qlog

import (
	"io"
	"time"

	"github.com/quic-go/quic-go/logging"
)

func NewTracer(w io.WriteCloser) *logging.Tracer {
	tr := &trace{
		VantagePoint: vantagePoint{Type: "transport"},
		CommonFields: commonFields{ReferenceTime: time.Now()},
	}
	wr := *newWriter(w, tr)
	go wr.Run()
	return &logging.Tracer{
		SentPacket:                   nil,
		SentVersionNegotiationPacket: nil,
		DroppedPacket:                nil,
		Debug: func(name, msg string) {
			wr.RecordEvent(time.Now(), &eventGeneric{
				name: name,
				msg:  msg,
			})
		},
		Close: func() { wr.Close() },
	}
}
