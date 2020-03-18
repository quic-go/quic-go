package qlog

import (
	"net"
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

type eventConnectionStarted struct {
	SrcAddr  *net.UDPAddr
	DestAddr *net.UDPAddr

	Version          protocol.VersionNumber
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID

	// TODO: add ALPN
}

var _ eventDetails = &eventConnectionStarted{}

func (e eventConnectionStarted) Category() category { return categoryTransport }
func (e eventConnectionStarted) Name() string       { return "connection_started" }
func (e eventConnectionStarted) IsNil() bool        { return false }

func (e eventConnectionStarted) MarshalJSONObject(enc *gojay.Encoder) {
	// If ip is not an IPv4 address, To4 returns nil.
	// Note that there might be some corner cases, where this is not correct.
	// See https://stackoverflow.com/questions/22751035/golang-distinguish-ipv4-ipv6.
	isIPv6 := e.SrcAddr.IP.To4() == nil
	if isIPv6 {
		enc.StringKey("ip_version", "ipv6")
	} else {
		enc.StringKey("ip_version", "ipv4")
	}
	enc.StringKey("src_ip", e.SrcAddr.IP.String())
	enc.IntKey("src_port", e.SrcAddr.Port)
	enc.StringKey("dst_ip", e.DestAddr.IP.String())
	enc.IntKey("dst_port", e.DestAddr.Port)
	enc.StringKey("quic_version", versionNumber(e.Version).String())
	enc.StringKey("src_cid", connectionID(e.SrcConnectionID).String())
	enc.StringKey("dst_cid", connectionID(e.DestConnectionID).String())
}

type eventPacketSent struct {
	PacketType  PacketType
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
	PacketType  PacketType
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
	enc.StringKey("packet_type", PacketTypeRetry.String())
	enc.ObjectKey("header", e.Header)
}

type eventPacketBuffered struct {
	PacketType PacketType
}

func (e eventPacketBuffered) Category() category { return categoryTransport }
func (e eventPacketBuffered) Name() string       { return "packet_buffered" }
func (e eventPacketBuffered) IsNil() bool        { return false }

func (e eventPacketBuffered) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", e.PacketType.String())
	enc.StringKey("trigger", "keys_unavailable")
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

type eventUpdatedPTO struct {
	Value uint32
}

func (e eventUpdatedPTO) Category() category { return categoryRecovery }
func (e eventUpdatedPTO) Name() string       { return "metrics_updated" }
func (e eventUpdatedPTO) IsNil() bool        { return false }

func (e eventUpdatedPTO) MarshalJSONObject(enc *gojay.Encoder) {
	enc.Uint32Key("pto_count", e.Value)
}

type eventPacketLost struct {
	PacketType   PacketType
	PacketNumber protocol.PacketNumber
	Trigger      PacketLossReason
}

func (e eventPacketLost) Category() category { return categoryRecovery }
func (e eventPacketLost) Name() string       { return "packet_lost" }
func (e eventPacketLost) IsNil() bool        { return false }

func (e eventPacketLost) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", e.PacketType.String())
	enc.Int64Key("packet_number", int64(e.PacketNumber))
	enc.StringKey("trigger", e.Trigger.String())
}

type eventKeyUpdated struct {
	Trigger    keyUpdateTrigger
	KeyType    keyType
	Generation protocol.KeyPhase
	// we don't log the keys here, so we don't need `old` and `new`.
}

func (e eventKeyUpdated) Category() category { return categorySecurity }
func (e eventKeyUpdated) Name() string       { return "key_updated" }
func (e eventKeyUpdated) IsNil() bool        { return false }

func (e eventKeyUpdated) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("trigger", e.Trigger.String())
	enc.StringKey("key_type", e.KeyType.String())
	enc.Uint64KeyOmitEmpty("generation", uint64(e.Generation))
}
