package qlog

import (
	"time"

	"github.com/francoispqt/gojay"
)

var eventFields = [4]string{"time", "category", "event", "data"}

type events []event

var _ gojay.MarshalerJSONArray = events{}

func (e events) IsNil() bool { return e == nil }
func (e events) MarshalJSONArray(enc *gojay.Encoder) {
	for _, ev := range e {
		enc.Array(ev)
	}
}

type eventDetails interface {
	Category() category
	Name() string
	gojay.MarshalerJSONObject
}

type event struct {
	Time time.Time
	eventDetails
}

var _ gojay.MarshalerJSONArray = event{}

func (e event) IsNil() bool { return false }
func (e event) MarshalJSONArray(enc *gojay.Encoder) {
	enc.Float64(float64(e.Time.UnixNano()) / 1e6)
	enc.String(e.Category().String())
	enc.String(e.Name())
	enc.Object(e.eventDetails)
}

type eventPacketSent struct {
	PacketType  packetType
	Header      packetHeader
	Frames      frames
	IsCoalesced bool
	Trigger     string
}

var _ eventDetails = eventPacketSent{}

func (e eventPacketSent) Category() category { return categoryTransport }
func (e eventPacketSent) Name() string       { return "packet_sent" }
func (e eventPacketSent) IsNil() bool        { return false }

func (e eventPacketSent) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", e.PacketType.String())
	enc.ObjectKey("header", e.Header)
	enc.ArrayKeyOmitEmpty("frames", e.Frames)
	enc.BoolKeyOmitEmpty("is_coalesced", e.IsCoalesced)
	enc.StringKeyOmitEmpty("trigger", e.Trigger)
}

type eventPacketReceived struct {
	PacketType  packetType
	Header      packetHeader
	Frames      frames
	IsCoalesced bool
	Trigger     string
}

var _ eventDetails = eventPacketReceived{}

func (e eventPacketReceived) Category() category { return categoryTransport }
func (e eventPacketReceived) Name() string       { return "packet_received" }
func (e eventPacketReceived) IsNil() bool        { return false }

func (e eventPacketReceived) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", e.PacketType.String())
	enc.ObjectKey("header", e.Header)
	enc.ArrayKeyOmitEmpty("frames", e.Frames)
	enc.BoolKeyOmitEmpty("is_coalesced", e.IsCoalesced)
	enc.StringKeyOmitEmpty("trigger", e.Trigger)
}

type eventRetryReceived struct {
	Header packetHeader
}

func (e eventRetryReceived) Category() category { return categoryTransport }
func (e eventRetryReceived) Name() string       { return "packet_received" }
func (e eventRetryReceived) IsNil() bool        { return false }

func (e eventRetryReceived) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", packetTypeRetry.String())
	enc.ObjectKey("header", e.Header)
}
