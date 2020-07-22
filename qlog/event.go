package qlog

import (
	"fmt"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/logging"

	"github.com/francoispqt/gojay"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

var eventFields = [4]string{"relative_time", "category", "event", "data"}

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
	RelativeTime time.Duration
	eventDetails
}

var _ gojay.MarshalerJSONArray = event{}

func (e event) IsNil() bool { return false }
func (e event) MarshalJSONArray(enc *gojay.Encoder) {
	enc.Float64(milliseconds(e.RelativeTime))
	enc.String(e.Category().String())
	enc.String(e.Name())
	enc.Object(e.eventDetails)
}

type versions []versionNumber

func (v versions) IsNil() bool { return false }
func (v versions) MarshalJSONArray(enc *gojay.Encoder) {
	for _, e := range v {
		enc.AddString(e.String())
	}
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

type eventConnectionClosed struct {
	Reason timeoutReason
}

func (e eventConnectionClosed) Category() category { return categoryTransport }
func (e eventConnectionClosed) Name() string       { return "connection_state_updated" }
func (e eventConnectionClosed) IsNil() bool        { return false }

func (e eventConnectionClosed) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("new", "closed")
	enc.StringKey("trigger", e.Reason.String())
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
	enc.StringKey("packet_type", packetType(logging.PacketTypeRetry).String())
	enc.ObjectKey("header", e.Header)
}

type eventVersionNegotiationReceived struct {
	Header            packetHeader
	SupportedVersions []versionNumber
}

func (e eventVersionNegotiationReceived) Category() category { return categoryTransport }
func (e eventVersionNegotiationReceived) Name() string       { return "packet_received" }
func (e eventVersionNegotiationReceived) IsNil() bool        { return false }

func (e eventVersionNegotiationReceived) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", packetType(logging.PacketTypeVersionNegotiation).String())
	enc.ObjectKey("header", e.Header)
	enc.ArrayKey("supported_versions", versions(e.SupportedVersions))
}

type eventStatelessResetReceived struct {
	Token protocol.StatelessResetToken
}

func (e eventStatelessResetReceived) Category() category { return categoryTransport }
func (e eventStatelessResetReceived) Name() string       { return "packet_received" }
func (e eventStatelessResetReceived) IsNil() bool        { return false }

func (e eventStatelessResetReceived) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", packetType(logging.PacketTypeStatelessReset).String())
	enc.StringKey("stateless_reset_token", fmt.Sprintf("%x", e.Token))
}

type eventPacketBuffered struct {
	PacketType packetType
}

func (e eventPacketBuffered) Category() category { return categoryTransport }
func (e eventPacketBuffered) Name() string       { return "packet_buffered" }
func (e eventPacketBuffered) IsNil() bool        { return false }

func (e eventPacketBuffered) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("packet_type", e.PacketType.String())
	enc.StringKey("trigger", "keys_unavailable")
}

type eventPacketDropped struct {
	PacketType packetType
	PacketSize protocol.ByteCount
	Trigger    packetDropReason
}

func (e eventPacketDropped) Category() category { return categoryTransport }
func (e eventPacketDropped) Name() string       { return "packet_dropped" }
func (e eventPacketDropped) IsNil() bool        { return false }

func (e eventPacketDropped) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKeyOmitEmpty("packet_type", e.PacketType.String())
	enc.Uint64Key("packet_size", uint64(e.PacketSize))
	enc.StringKey("trigger", e.Trigger.String())
}

type metrics struct {
	MinRTT      time.Duration
	SmoothedRTT time.Duration
	LatestRTT   time.Duration
	RTTVariance time.Duration

	CongestionWindow protocol.ByteCount
	BytesInFlight    protocol.ByteCount
	PacketsInFlight  int
}

type eventMetricsUpdated struct {
	Last    *metrics
	Current *metrics
}

func (e eventMetricsUpdated) Category() category { return categoryRecovery }
func (e eventMetricsUpdated) Name() string       { return "metrics_updated" }
func (e eventMetricsUpdated) IsNil() bool        { return false }

func (e eventMetricsUpdated) MarshalJSONObject(enc *gojay.Encoder) {
	if e.Last == nil || e.Last.MinRTT != e.Current.MinRTT {
		enc.FloatKey("min_rtt", milliseconds(e.Current.MinRTT))
	}
	if e.Last == nil || e.Last.SmoothedRTT != e.Current.SmoothedRTT {
		enc.FloatKey("smoothed_rtt", milliseconds(e.Current.SmoothedRTT))
	}
	if e.Last == nil || e.Last.LatestRTT != e.Current.LatestRTT {
		enc.FloatKey("latest_rtt", milliseconds(e.Current.LatestRTT))
	}
	if e.Last == nil || e.Last.RTTVariance != e.Current.RTTVariance {
		enc.FloatKey("rtt_variance", milliseconds(e.Current.RTTVariance))
	}

	if e.Last == nil || e.Last.CongestionWindow != e.Current.CongestionWindow {
		enc.Uint64Key("congestion_window", uint64(e.Current.CongestionWindow))
	}
	if e.Last == nil || e.Last.BytesInFlight != e.Current.BytesInFlight {
		enc.Uint64Key("bytes_in_flight", uint64(e.Current.BytesInFlight))
	}
	if e.Last == nil || e.Last.PacketsInFlight != e.Current.PacketsInFlight {
		enc.Uint64KeyOmitEmpty("packets_in_flight", uint64(e.Current.PacketsInFlight))
	}
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
	PacketType   packetType
	PacketNumber protocol.PacketNumber
	Trigger      packetLossReason
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

type eventKeyRetired struct {
	KeyType    keyType
	Generation protocol.KeyPhase
}

func (e eventKeyRetired) Category() category { return categorySecurity }
func (e eventKeyRetired) Name() string       { return "key_retired" }
func (e eventKeyRetired) IsNil() bool        { return false }

func (e eventKeyRetired) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("trigger", "tls")
	enc.StringKey("key_type", e.KeyType.String())
}

type eventTransportParameters struct {
	Owner  owner
	SentBy protocol.Perspective

	OriginalDestinationConnectionID protocol.ConnectionID
	InitialSourceConnectionID       protocol.ConnectionID
	RetrySourceConnectionID         *protocol.ConnectionID

	StatelessResetToken     *protocol.StatelessResetToken
	DisableActiveMigration  bool
	MaxIdleTimeout          time.Duration
	MaxUDPPayloadSize       protocol.ByteCount
	AckDelayExponent        uint8
	MaxAckDelay             time.Duration
	ActiveConnectionIDLimit uint64

	InitialMaxData                 protocol.ByteCount
	InitialMaxStreamDataBidiLocal  protocol.ByteCount
	InitialMaxStreamDataBidiRemote protocol.ByteCount
	InitialMaxStreamDataUni        protocol.ByteCount
	InitialMaxStreamsBidi          int64
	InitialMaxStreamsUni           int64

	// TODO: add the preferred_address
}

func (e eventTransportParameters) Category() category { return categoryTransport }
func (e eventTransportParameters) Name() string       { return "parameters_set" }
func (e eventTransportParameters) IsNil() bool        { return false }

func (e eventTransportParameters) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("owner", e.Owner.String())
	if e.SentBy == protocol.PerspectiveServer {
		enc.StringKey("original_destination_connection_id", connectionID(e.OriginalDestinationConnectionID).String())
		if e.StatelessResetToken != nil {
			enc.StringKey("stateless_reset_token", fmt.Sprintf("%x", e.StatelessResetToken[:]))
		}
		if e.RetrySourceConnectionID != nil {
			enc.StringKey("retry_source_connection_id", connectionID(*e.RetrySourceConnectionID).String())
		}
	}
	enc.StringKey("initial_source_connection_id", connectionID(e.InitialSourceConnectionID).String())
	enc.BoolKey("disable_active_migration", e.DisableActiveMigration)
	enc.FloatKeyOmitEmpty("max_idle_timeout", milliseconds(e.MaxIdleTimeout))
	enc.Uint64KeyNullEmpty("max_udp_payload_size", uint64(e.MaxUDPPayloadSize))
	enc.Uint8KeyOmitEmpty("ack_delay_exponent", e.AckDelayExponent)
	enc.FloatKeyOmitEmpty("max_ack_delay", milliseconds(e.MaxAckDelay))
	enc.Uint64KeyOmitEmpty("active_connection_id_limit", e.ActiveConnectionIDLimit)

	enc.Int64KeyOmitEmpty("initial_max_data", int64(e.InitialMaxData))
	enc.Int64KeyOmitEmpty("initial_max_stream_data_bidi_local", int64(e.InitialMaxStreamDataBidiLocal))
	enc.Int64KeyOmitEmpty("initial_max_stream_data_bidi_remote", int64(e.InitialMaxStreamDataBidiRemote))
	enc.Int64KeyOmitEmpty("initial_max_stream_data_uni", int64(e.InitialMaxStreamDataUni))
	enc.Int64KeyOmitEmpty("initial_max_streams_bidi", e.InitialMaxStreamsBidi)
	enc.Int64KeyOmitEmpty("initial_max_streams_uni", e.InitialMaxStreamsUni)
}

type eventLossTimerSet struct {
	TimerType timerType
	EncLevel  protocol.EncryptionLevel
	Delta     time.Duration
}

func (e eventLossTimerSet) Category() category { return categoryRecovery }
func (e eventLossTimerSet) Name() string       { return "loss_timer_updated" }
func (e eventLossTimerSet) IsNil() bool        { return false }

func (e eventLossTimerSet) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("event_type", "set")
	enc.StringKey("timer_type", e.TimerType.String())
	enc.StringKey("packet_number_space", encLevelToPacketNumberSpace(e.EncLevel))
	enc.Float64Key("delta", milliseconds(e.Delta))
}

type eventLossTimerExpired struct {
	TimerType timerType
	EncLevel  protocol.EncryptionLevel
}

func (e eventLossTimerExpired) Category() category { return categoryRecovery }
func (e eventLossTimerExpired) Name() string       { return "loss_timer_updated" }
func (e eventLossTimerExpired) IsNil() bool        { return false }

func (e eventLossTimerExpired) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("event_type", "expired")
	enc.StringKey("timer_type", e.TimerType.String())
	enc.StringKey("packet_number_space", encLevelToPacketNumberSpace(e.EncLevel))
}

type eventLossTimerCanceled struct{}

func (e eventLossTimerCanceled) Category() category { return categoryRecovery }
func (e eventLossTimerCanceled) Name() string       { return "loss_timer_updated" }
func (e eventLossTimerCanceled) IsNil() bool        { return false }

func (e eventLossTimerCanceled) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("event_type", "cancelled")
}

type eventCongestionStateUpdated struct {
	state congestionState
}

func (e eventCongestionStateUpdated) Category() category { return categoryRecovery }
func (e eventCongestionStateUpdated) Name() string       { return "congestion_state_updated" }
func (e eventCongestionStateUpdated) IsNil() bool        { return false }

func (e eventCongestionStateUpdated) MarshalJSONObject(enc *gojay.Encoder) {
	enc.StringKey("new", e.state.String())
}
