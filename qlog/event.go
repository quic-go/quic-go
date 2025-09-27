package qlog

import (
	"time"

	"github.com/francoispqt/gojay"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

type event struct {
	RelativeTime time.Duration
	Event
}

type wrappedEvent struct {
	Event
}

func (e *wrappedEvent) IsNil() bool { return false }

func (e *event) MarshalJSONObject(enc *gojay.Encoder) {
	enc.Float64Key("time", milliseconds(e.RelativeTime))
	enc.StringKey("name", e.Event.Name())
	enc.ObjectKey("data", &wrappedEvent{Event: e.Event})
}

func (e *event) IsNil() bool { return false }

var _ gojay.MarshalerJSONObject = &event{}

type Event interface {
	Name() string
	MarshalJSONObject(*gojay.Encoder)
}
