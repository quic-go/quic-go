package qlog

import (
	"sort"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	"github.com/francoispqt/gojay"
)

var eventFields = [4]string{"time", "category", "event", "data"}

type events []event

var _ sort.Interface = &events{}
var _ gojay.MarshalerJSONArray = events{}

func (e events) IsNil() bool { return e == nil }
func (e events) Len() int    { return len(e) }
func (e events) Less(i, j int) bool {
	// Don't use time.Before() here.
	// Before() uses monotonic time.
	// We need to make sure that the actual exported timestamp are sorted.
	return e[i].Time.UnixNano() < e[j].Time.UnixNano()
}
func (e events) Swap(i, j int) { e[i], e[j] = e[j], e[i] }

func (e events) MarshalJSONArray(enc *gojay.Encoder) {
	// Event timestamps are taken from multiple go routines.
	// For example, the receiving go routine sets the receive time of the packet.
	// Therefore, events can end up being slightly out of order.
	// It turns out that Go's stable sort implementation is a lot faster in that case.
	// See https://gist.github.com/marten-seemann/30251742b378318097e5400ea170c00f for benchmarking code.
	sort.Stable(e)
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

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

type eventMetricsUpdated struct {
	MinRTT      time.Duration
	SmoothedRTT time.Duration
	LatestRTT   time.Duration
	RTTVariance time.Duration

	CongestionWindow protocol.ByteCount
	BytesInFlight    protocol.ByteCount
	PacketsInFlight  int
}

func (e eventMetricsUpdated) Category() category { return categoryRecovery }
func (e eventMetricsUpdated) Name() string       { return "metrics_updated" }
func (e eventMetricsUpdated) IsNil() bool        { return false }

func (e eventMetricsUpdated) MarshalJSONObject(enc *gojay.Encoder) {
	enc.FloatKey("min_rtt", milliseconds(e.MinRTT))
	enc.FloatKey("smoothed_rtt", milliseconds(e.SmoothedRTT))
	enc.FloatKey("latest_rtt", milliseconds(e.LatestRTT))
	enc.FloatKey("rtt_variance", milliseconds(e.RTTVariance))

	enc.Uint64Key("congestion_window", uint64(e.CongestionWindow))
	enc.Uint64Key("bytes_in_flight", uint64(e.BytesInFlight))
	enc.Uint64KeyOmitEmpty("packets_in_flight", uint64(e.PacketsInFlight))
}

type eventPacketLost struct {
	PacketType   packetType
	PacketNumber protocol.PacketNumber
	Trigger      PacketLossReason
}

func (e eventPacketLost) Category() category { return categoryRecovery }
func (e eventPacketLost) Name() string       { return "packet_lost" }
func (e eventPacketLost) IsNil() bool        { return false }

func (e eventPacketLost) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", e.PacketType.String())
	enc.StringKey("packet_number", toString(int64(e.PacketNumber)))
	enc.StringKey("trigger", e.Trigger.String())
}
