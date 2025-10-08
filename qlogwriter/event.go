package qlogwriter

import (
	"time"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

// Event represents a qlog event that can be encoded to JSON.
// Each event must provide its name and a method to encode itself using a jsontext.Encoder.
type Event interface {
	// Name returns the name of the event, as it should appear in the qlog output
	Name() string
	// Encode writes the event's data to the provided jsontext.Encoder
	Encode(*jsontext.Encoder) error
}

type event struct {
	RelativeTime time.Duration
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
	h.WriteToken(jsontext.String(e.Name()))
	h.WriteToken(jsontext.String("data"))
	if err := e.Event.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
