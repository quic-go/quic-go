package qlog

import (
	"time"

	"github.com/quic-go/quic-go/qlog/jsontext"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

type Event interface {
	Name() string
	Encode(*jsontext.Encoder) error
}

type event struct {
	RelativeTime time.Duration
	Event
}

type wrappedEvent struct {
	Event
}

type encoderHelper struct {
	enc *jsontext.Encoder
	err error
}

func (h *encoderHelper) WriteToken(t jsontext.Token) {
	if h.err != nil {
		return
	}
	h.err = h.enc.WriteToken(t)
}

func (e *event) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("time"))
	h.WriteToken(jsontext.Float(milliseconds(e.RelativeTime)))
	h.WriteToken(jsontext.String("name"))
	h.WriteToken(jsontext.String(e.Event.Name()))
	h.WriteToken(jsontext.String("data"))
	if err := e.Event.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
