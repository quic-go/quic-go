package qlog

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog/jsontext"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

type eventDetails interface {
	Name() string
	Encode(*jsontext.Encoder) error
}

type event struct {
	RelativeTime time.Duration
	eventDetails
}

type jsontextEncoder interface {
	Encode(*jsontext.Encoder) error
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

func (e event) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("time"))
	h.WriteToken(jsontext.Float(milliseconds(e.RelativeTime)))
	h.WriteToken(jsontext.String("name"))
	h.WriteToken(jsontext.String(e.Name()))
	h.WriteToken(jsontext.String("data"))
	if err := e.eventDetails.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type versions []version

func (v versions) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginArray)
	for _, e := range v {
		h.WriteToken(jsontext.String(e.String()))
	}
	h.WriteToken(jsontext.EndArray)
	return h.err
}

type rawInfo struct {
	Length        logging.ByteCount // full packet length, including header and AEAD authentication tag
	PayloadLength logging.ByteCount // length of the packet payload, excluding AEAD tag
}

func (i rawInfo) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("length"))
	h.WriteToken(jsontext.Uint(uint64(i.Length)))
	if i.PayloadLength != 0 {
		h.WriteToken(jsontext.String("payload_length"))
		h.WriteToken(jsontext.Uint(uint64(i.PayloadLength)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventConnectionStarted struct {
	SrcAddr          *net.UDPAddr
	DestAddr         *net.UDPAddr
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID
}

func (e eventConnectionStarted) Name() string { return "transport:connection_started" }

func (e eventConnectionStarted) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.SrcAddr.IP.To4() != nil {
		h.WriteToken(jsontext.String("ip_version"))
		h.WriteToken(jsontext.String("ipv4"))
	} else {
		h.WriteToken(jsontext.String("ip_version"))
		h.WriteToken(jsontext.String("ipv6"))
	}
	h.WriteToken(jsontext.String("src_ip"))
	h.WriteToken(jsontext.String(e.SrcAddr.IP.String()))
	h.WriteToken(jsontext.String("src_port"))
	h.WriteToken(jsontext.Int(int64(e.SrcAddr.Port)))
	h.WriteToken(jsontext.String("dst_ip"))
	h.WriteToken(jsontext.String(e.DestAddr.IP.String()))
	h.WriteToken(jsontext.String("dst_port"))
	h.WriteToken(jsontext.Int(int64(e.DestAddr.Port)))
	h.WriteToken(jsontext.String("src_cid"))
	h.WriteToken(jsontext.String(e.SrcConnectionID.String()))
	h.WriteToken(jsontext.String("dst_cid"))
	h.WriteToken(jsontext.String(e.DestConnectionID.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventVersionNegotiated struct {
	clientVersions, serverVersions []version
	chosenVersion                  version
}

func (e eventVersionNegotiated) Name() string { return "transport:version_information" }

func (e eventVersionNegotiated) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if len(e.clientVersions) > 0 {
		h.WriteToken(jsontext.String("client_versions"))
		if err := versions(e.clientVersions).Encode(enc); err != nil {
			return err
		}
	}
	if len(e.serverVersions) > 0 {
		h.WriteToken(jsontext.String("server_versions"))
		if err := versions(e.serverVersions).Encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.String("chosen_version"))
	h.WriteToken(jsontext.String(e.chosenVersion.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventConnectionClosed struct {
	e error
}

func (e eventConnectionClosed) Name() string { return "transport:connection_closed" }

func (e eventConnectionClosed) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	var (
		statelessResetErr     *quic.StatelessResetError
		handshakeTimeoutErr   *quic.HandshakeTimeoutError
		idleTimeoutErr        *quic.IdleTimeoutError
		applicationErr        *quic.ApplicationError
		transportErr          *quic.TransportError
		versionNegotiationErr *quic.VersionNegotiationError
	)
	switch {
	case errors.As(e.e, &statelessResetErr):
		h.WriteToken(jsontext.String("owner"))
		h.WriteToken(jsontext.String(ownerRemote.String()))
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("stateless_reset"))
	case errors.As(e.e, &handshakeTimeoutErr):
		h.WriteToken(jsontext.String("owner"))
		h.WriteToken(jsontext.String(ownerLocal.String()))
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("handshake_timeout"))
	case errors.As(e.e, &idleTimeoutErr):
		h.WriteToken(jsontext.String("owner"))
		h.WriteToken(jsontext.String(ownerLocal.String()))
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("idle_timeout"))
	case errors.As(e.e, &applicationErr):
		owner := ownerLocal
		if applicationErr.Remote {
			owner = ownerRemote
		}
		h.WriteToken(jsontext.String("owner"))
		h.WriteToken(jsontext.String(owner.String()))
		h.WriteToken(jsontext.String("application_code"))
		h.WriteToken(jsontext.Uint(uint64(applicationErr.ErrorCode)))
		h.WriteToken(jsontext.String("reason"))
		h.WriteToken(jsontext.String(applicationErr.ErrorMessage))
	case errors.As(e.e, &transportErr):
		owner := ownerLocal
		if transportErr.Remote {
			owner = ownerRemote
		}
		h.WriteToken(jsontext.String("owner"))
		h.WriteToken(jsontext.String(owner.String()))
		h.WriteToken(jsontext.String("connection_code"))
		h.WriteToken(jsontext.String(transportError(transportErr.ErrorCode).String()))
		h.WriteToken(jsontext.String("reason"))
		h.WriteToken(jsontext.String(transportErr.ErrorMessage))
	case errors.As(e.e, &versionNegotiationErr):
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("version_mismatch"))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventPacketSent struct {
	Header        jsontextEncoder // either a shortHeader or a packetHeader
	Length        logging.ByteCount
	PayloadLength logging.ByteCount
	Frames        frames
	IsCoalesced   bool
	ECN           logging.ECN
	Trigger       string
}

func (e eventPacketSent) Name() string { return "transport:packet_sent" }

func (e eventPacketSent) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := (rawInfo{Length: e.Length, PayloadLength: e.PayloadLength}).Encode(enc); err != nil {
		return err
	}
	if len(e.Frames) > 0 {
		h.WriteToken(jsontext.String("frames"))
		if err := e.Frames.Encode(enc); err != nil {
			return err
		}
	}
	if e.IsCoalesced {
		h.WriteToken(jsontext.String("is_coalesced"))
		h.WriteToken(jsontext.True)
	}
	if e.ECN != logging.ECNUnsupported {
		h.WriteToken(jsontext.String("ecn"))
		h.WriteToken(jsontext.String(ecn(e.ECN).String()))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventPacketReceived struct {
	Header        jsontextEncoder // either a shortHeader or a packetHeader
	Length        logging.ByteCount
	PayloadLength logging.ByteCount
	Frames        frames
	ECN           logging.ECN
	IsCoalesced   bool
	Trigger       string
}

func (e eventPacketReceived) Name() string { return "transport:packet_received" }

func (e eventPacketReceived) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := (rawInfo{Length: e.Length, PayloadLength: e.PayloadLength}).Encode(enc); err != nil {
		return err
	}
	if len(e.Frames) > 0 {
		h.WriteToken(jsontext.String("frames"))
		if err := e.Frames.Encode(enc); err != nil {
			return err
		}
	}
	if e.IsCoalesced {
		h.WriteToken(jsontext.String("is_coalesced"))
		h.WriteToken(jsontext.True)
	}
	if e.ECN != logging.ECNUnsupported {
		h.WriteToken(jsontext.String("ecn"))
		h.WriteToken(jsontext.String(ecn(e.ECN).String()))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventRetryReceived struct {
	Header packetHeader
}

func (e eventRetryReceived) Name() string { return "transport:packet_received" }

func (e eventRetryReceived) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventVersionNegotiationReceived struct {
	Header            packetHeaderVersionNegotiation
	SupportedVersions []version
}

func (e eventVersionNegotiationReceived) Name() string { return "transport:packet_received" }

func (e eventVersionNegotiationReceived) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("supported_versions"))
	if err := versions(e.SupportedVersions).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventVersionNegotiationSent struct {
	Header            packetHeaderVersionNegotiation
	SupportedVersions []version
}

func (e eventVersionNegotiationSent) Name() string { return "transport:packet_sent" }

func (e eventVersionNegotiationSent) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("supported_versions"))
	if err := versions(e.SupportedVersions).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventPacketBuffered struct {
	PacketType logging.PacketType
	PacketSize protocol.ByteCount
}

func (e eventPacketBuffered) Name() string { return "transport:packet_buffered" }

func (e eventPacketBuffered) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := (packetHeaderWithType{
		PacketType:   e.PacketType,
		PacketNumber: protocol.InvalidPacketNumber,
	}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := (rawInfo{Length: e.PacketSize}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String("keys_unavailable"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventPacketDropped struct {
	PacketType   logging.PacketType
	PacketSize   protocol.ByteCount
	PacketNumber logging.PacketNumber
	Trigger      packetDropReason
}

func (e eventPacketDropped) Name() string { return "transport:packet_dropped" }

func (e eventPacketDropped) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := (packetHeaderWithType{
		PacketType:   e.PacketType,
		PacketNumber: e.PacketNumber,
	}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := (rawInfo{Length: e.PacketSize}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(e.Trigger.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type metrics struct {
	MinRTT           time.Duration
	SmoothedRTT      time.Duration
	LatestRTT        time.Duration
	RTTVariance      time.Duration
	CongestionWindow protocol.ByteCount
	BytesInFlight    protocol.ByteCount
	PacketsInFlight  int
}

type eventMTUUpdated struct {
	mtu  protocol.ByteCount
	done bool
}

func (e eventMTUUpdated) Name() string { return "recovery:mtu_updated" }

func (e eventMTUUpdated) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("mtu"))
	h.WriteToken(jsontext.Uint(uint64(e.mtu)))
	h.WriteToken(jsontext.String("done"))
	h.WriteToken(jsontext.Bool(e.done))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventMetricsUpdated struct {
	Last    *metrics
	Current *metrics
}

func (e eventMetricsUpdated) Name() string { return "recovery:metrics_updated" }

func (e eventMetricsUpdated) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.Last == nil || e.Last.MinRTT != e.Current.MinRTT {
		h.WriteToken(jsontext.String("min_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.Current.MinRTT)))
	}
	if e.Last == nil || e.Last.SmoothedRTT != e.Current.SmoothedRTT {
		h.WriteToken(jsontext.String("smoothed_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.Current.SmoothedRTT)))
	}
	if e.Last == nil || e.Last.LatestRTT != e.Current.LatestRTT {
		h.WriteToken(jsontext.String("latest_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.Current.LatestRTT)))
	}
	if e.Last == nil || e.Last.RTTVariance != e.Current.RTTVariance {
		h.WriteToken(jsontext.String("rtt_variance"))
		h.WriteToken(jsontext.Float(milliseconds(e.Current.RTTVariance)))
	}
	if e.Last == nil || e.Last.CongestionWindow != e.Current.CongestionWindow {
		h.WriteToken(jsontext.String("congestion_window"))
		h.WriteToken(jsontext.Uint(uint64(e.Current.CongestionWindow)))
	}
	if e.Last == nil || e.Last.BytesInFlight != e.Current.BytesInFlight {
		h.WriteToken(jsontext.String("bytes_in_flight"))
		h.WriteToken(jsontext.Uint(uint64(e.Current.BytesInFlight)))
	}
	if e.Last == nil || e.Last.PacketsInFlight != e.Current.PacketsInFlight {
		h.WriteToken(jsontext.String("packets_in_flight"))
		h.WriteToken(jsontext.Uint(uint64(e.Current.PacketsInFlight)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventUpdatedPTO struct {
	Value uint32
}

func (e eventUpdatedPTO) Name() string { return "recovery:metrics_updated" }

func (e eventUpdatedPTO) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("pto_count"))
	h.WriteToken(jsontext.Uint(uint64(e.Value)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventPacketLost struct {
	PacketType   logging.PacketType
	PacketNumber protocol.PacketNumber
	Trigger      packetLossReason
}

func (e eventPacketLost) Name() string { return "recovery:packet_lost" }

func (e eventPacketLost) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := (packetHeaderWithTypeAndPacketNumber{
		PacketType:   e.PacketType,
		PacketNumber: e.PacketNumber,
	}).Encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(e.Trigger.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventSpuriousLoss struct {
	EncLevel     protocol.EncryptionLevel
	PacketNumber protocol.PacketNumber
	Reordering   uint64
	Duration     time.Duration
}

func (e eventSpuriousLoss) Name() string { return "recovery:spurious_loss" }

func (e eventSpuriousLoss) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_number_space"))
	h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel)))
	h.WriteToken(jsontext.String("packet_number"))
	h.WriteToken(jsontext.Uint(uint64(e.PacketNumber)))
	h.WriteToken(jsontext.String("reordering_packets"))
	h.WriteToken(jsontext.Uint(e.Reordering))
	h.WriteToken(jsontext.String("reordering_time"))
	h.WriteToken(jsontext.Float(milliseconds(e.Duration)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventKeyUpdated struct {
	Trigger  keyUpdateTrigger
	KeyType  keyType
	KeyPhase protocol.KeyPhase
	// we don't log the keys here, so we don't need `old` and `new`.
}

func (e eventKeyUpdated) Name() string { return "security:key_updated" }

func (e eventKeyUpdated) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(e.Trigger.String()))
	h.WriteToken(jsontext.String("key_type"))
	h.WriteToken(jsontext.String(e.KeyType.String()))
	if e.KeyType == keyTypeClient1RTT || e.KeyType == keyTypeServer1RTT {
		h.WriteToken(jsontext.String("key_phase"))
		h.WriteToken(jsontext.Uint(uint64(e.KeyPhase)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventKeyDiscarded struct {
	KeyType  keyType
	KeyPhase protocol.KeyPhase
}

func (e eventKeyDiscarded) Name() string { return "security:key_discarded" }

func (e eventKeyDiscarded) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.KeyType != keyTypeClient1RTT && e.KeyType != keyTypeServer1RTT {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("tls"))
	}
	h.WriteToken(jsontext.String("key_type"))
	h.WriteToken(jsontext.String(e.KeyType.String()))
	if e.KeyType == keyTypeClient1RTT || e.KeyType == keyTypeServer1RTT {
		h.WriteToken(jsontext.String("key_phase"))
		h.WriteToken(jsontext.Uint(uint64(e.KeyPhase)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventTransportParameters struct {
	Restore                         bool
	Owner                           owner
	SentBy                          protocol.Perspective
	OriginalDestinationConnectionID protocol.ConnectionID
	InitialSourceConnectionID       protocol.ConnectionID
	RetrySourceConnectionID         *protocol.ConnectionID
	StatelessResetToken             *protocol.StatelessResetToken
	DisableActiveMigration          bool
	MaxIdleTimeout                  time.Duration
	MaxUDPPayloadSize               protocol.ByteCount
	AckDelayExponent                uint8
	MaxAckDelay                     time.Duration
	ActiveConnectionIDLimit         uint64
	InitialMaxData                  protocol.ByteCount
	InitialMaxStreamDataBidiLocal   protocol.ByteCount
	InitialMaxStreamDataBidiRemote  protocol.ByteCount
	InitialMaxStreamDataUni         protocol.ByteCount
	InitialMaxStreamsBidi           int64
	InitialMaxStreamsUni            int64
	PreferredAddress                *preferredAddress
	MaxDatagramFrameSize            protocol.ByteCount
	EnableResetStreamAt             bool
}

func (e eventTransportParameters) Name() string {
	if e.Restore {
		return "transport:parameters_restored"
	}
	return "transport:parameters_set"
}

func (e eventTransportParameters) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if !e.Restore {
		h.WriteToken(jsontext.String("owner"))
		h.WriteToken(jsontext.String(e.Owner.String()))
		if e.SentBy == protocol.PerspectiveServer {
			h.WriteToken(jsontext.String("original_destination_connection_id"))
			h.WriteToken(jsontext.String(e.OriginalDestinationConnectionID.String()))
			if e.StatelessResetToken != nil {
				h.WriteToken(jsontext.String("stateless_reset_token"))
				h.WriteToken(jsontext.String(fmt.Sprintf("%x", e.StatelessResetToken[:])))
			}
			if e.RetrySourceConnectionID != nil {
				h.WriteToken(jsontext.String("retry_source_connection_id"))
				h.WriteToken(jsontext.String((*e.RetrySourceConnectionID).String()))
			}
		}
		h.WriteToken(jsontext.String("initial_source_connection_id"))
		h.WriteToken(jsontext.String(e.InitialSourceConnectionID.String()))
	}
	h.WriteToken(jsontext.String("disable_active_migration"))
	h.WriteToken(jsontext.Bool(e.DisableActiveMigration))
	if e.MaxIdleTimeout != 0 {
		h.WriteToken(jsontext.String("max_idle_timeout"))
		h.WriteToken(jsontext.Float(milliseconds(e.MaxIdleTimeout)))
	}
	if e.MaxUDPPayloadSize != 0 {
		h.WriteToken(jsontext.String("max_udp_payload_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxUDPPayloadSize)))
	}
	if e.AckDelayExponent != 0 {
		h.WriteToken(jsontext.String("ack_delay_exponent"))
		h.WriteToken(jsontext.Uint(uint64(e.AckDelayExponent)))
	}
	if e.MaxAckDelay != 0 {
		h.WriteToken(jsontext.String("max_ack_delay"))
		h.WriteToken(jsontext.Float(milliseconds(e.MaxAckDelay)))
	}
	if e.ActiveConnectionIDLimit != 0 {
		h.WriteToken(jsontext.String("active_connection_id_limit"))
		h.WriteToken(jsontext.Uint(e.ActiveConnectionIDLimit))
	}
	if e.InitialMaxData != 0 {
		h.WriteToken(jsontext.String("initial_max_data"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxData)))
	}
	if e.InitialMaxStreamDataBidiLocal != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_local"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiLocal)))
	}
	if e.InitialMaxStreamDataBidiRemote != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_remote"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiRemote)))
	}
	if e.InitialMaxStreamDataUni != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_uni"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataUni)))
	}
	if e.InitialMaxStreamsBidi != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_bidi"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsBidi))
	}
	if e.InitialMaxStreamsUni != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_uni"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsUni))
	}
	if e.PreferredAddress != nil {
		h.WriteToken(jsontext.String("preferred_address"))
		if err := e.PreferredAddress.Encode(enc); err != nil {
			return err
		}
	}
	if e.MaxDatagramFrameSize != protocol.InvalidByteCount {
		h.WriteToken(jsontext.String("max_datagram_frame_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxDatagramFrameSize)))
	}
	if e.EnableResetStreamAt {
		h.WriteToken(jsontext.String("reset_stream_at"))
		h.WriteToken(jsontext.True)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type preferredAddress struct {
	IPv4, IPv6          netip.AddrPort
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func (a preferredAddress) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if a.IPv4.IsValid() {
		h.WriteToken(jsontext.String("ip_v4"))
		h.WriteToken(jsontext.String(a.IPv4.Addr().String()))
		h.WriteToken(jsontext.String("port_v4"))
		h.WriteToken(jsontext.Uint(uint64(a.IPv4.Port())))
	}
	if a.IPv6.IsValid() {
		h.WriteToken(jsontext.String("ip_v6"))
		h.WriteToken(jsontext.String(a.IPv6.Addr().String()))
		h.WriteToken(jsontext.String("port_v6"))
		h.WriteToken(jsontext.Uint(uint64(a.IPv6.Port())))
	}
	h.WriteToken(jsontext.String("connection_id"))
	h.WriteToken(jsontext.String(a.ConnectionID.String()))
	h.WriteToken(jsontext.String("stateless_reset_token"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", a.StatelessResetToken)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventLossTimerSet struct {
	TimerType timerType
	EncLevel  protocol.EncryptionLevel
	Delta     time.Duration
}

func (e eventLossTimerSet) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerSet) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("event_type"))
	h.WriteToken(jsontext.String("set"))
	h.WriteToken(jsontext.String("timer_type"))
	h.WriteToken(jsontext.String(e.TimerType.String()))
	h.WriteToken(jsontext.String("packet_number_space"))
	h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel)))
	h.WriteToken(jsontext.String("delta"))
	h.WriteToken(jsontext.Float(milliseconds(e.Delta)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventLossTimerExpired struct {
	TimerType timerType
	EncLevel  protocol.EncryptionLevel
}

func (e eventLossTimerExpired) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerExpired) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("event_type"))
	h.WriteToken(jsontext.String("expired"))
	h.WriteToken(jsontext.String("timer_type"))
	h.WriteToken(jsontext.String(e.TimerType.String()))
	h.WriteToken(jsontext.String("packet_number_space"))
	h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventLossTimerCanceled struct{}

func (e eventLossTimerCanceled) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerCanceled) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("event_type"))
	h.WriteToken(jsontext.String("cancelled"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventCongestionStateUpdated struct {
	state congestionState
}

func (e eventCongestionStateUpdated) Name() string { return "recovery:congestion_state_updated" }

func (e eventCongestionStateUpdated) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(e.state.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventECNStateUpdated struct {
	state   logging.ECNState
	trigger logging.ECNStateTrigger
}

func (e eventECNStateUpdated) Name() string { return "recovery:ecn_state_updated" }

func (e eventECNStateUpdated) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(ecnState(e.state).String()))
	if e.trigger != 0 {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(ecnStateTrigger(e.trigger).String()))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventALPNInformation struct {
	chosenALPN string
}

func (e eventALPNInformation) Name() string { return "transport:alpn_information" }

func (e eventALPNInformation) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("chosen_alpn"))
	h.WriteToken(jsontext.String(e.chosenALPN))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventGeneric struct {
	name string
	msg  string
}

func (e eventGeneric) Name() string { return "transport:" + e.name }

func (e eventGeneric) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("details"))
	h.WriteToken(jsontext.String(e.msg))
	h.WriteToken(jsontext.EndObject)
	return h.err
}
