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

func (e event) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("time")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Float(milliseconds(e.RelativeTime))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("name")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.Name())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("data")); err != nil {
		return err
	}
	if err := e.eventDetails.Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type versions []version

func (v versions) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginArray); err != nil {
		return err
	}
	for _, e := range v {
		if err := enc.WriteToken(jsontext.String(e.String())); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndArray)
}

type rawInfo struct {
	Length        logging.ByteCount // full packet length, including header and AEAD authentication tag
	PayloadLength logging.ByteCount // length of the packet payload, excluding AEAD tag
}

func (i rawInfo) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("length")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(i.Length))); err != nil {
		return err
	}
	if i.PayloadLength != 0 {
		if err := enc.WriteToken(jsontext.String("payload_length")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(i.PayloadLength))); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventConnectionStarted struct {
	SrcAddr          *net.UDPAddr
	DestAddr         *net.UDPAddr
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID
}

func (e eventConnectionStarted) Name() string { return "transport:connection_started" }

func (e eventConnectionStarted) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if e.SrcAddr.IP.To4() != nil {
		if err := enc.WriteToken(jsontext.String("ip_version")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("ipv4")); err != nil {
			return err
		}
	} else {
		if err := enc.WriteToken(jsontext.String("ip_version")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("ipv6")); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("src_ip")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.SrcAddr.IP.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("src_port")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(e.SrcAddr.Port))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("dst_ip")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.DestAddr.IP.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("dst_port")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Int(int64(e.DestAddr.Port))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("src_cid")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.SrcConnectionID.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("dst_cid")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.DestConnectionID.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventVersionNegotiated struct {
	clientVersions, serverVersions []version
	chosenVersion                  version
}

func (e eventVersionNegotiated) Name() string { return "transport:version_information" }

func (e eventVersionNegotiated) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if len(e.clientVersions) > 0 {
		if err := enc.WriteToken(jsontext.String("client_versions")); err != nil {
			return err
		}
		if err := versions(e.clientVersions).Encode(enc); err != nil {
			return err
		}
	}
	if len(e.serverVersions) > 0 {
		if err := enc.WriteToken(jsontext.String("server_versions")); err != nil {
			return err
		}
		if err := versions(e.serverVersions).Encode(enc); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("chosen_version")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.chosenVersion.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventConnectionClosed struct {
	e error
}

func (e eventConnectionClosed) Name() string { return "transport:connection_closed" }

func (e eventConnectionClosed) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}

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
		if err := enc.WriteToken(jsontext.String("owner")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(ownerRemote.String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("stateless_reset")); err != nil {
			return err
		}
	case errors.As(e.e, &handshakeTimeoutErr):
		if err := enc.WriteToken(jsontext.String("owner")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(ownerLocal.String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("handshake_timeout")); err != nil {
			return err
		}
	case errors.As(e.e, &idleTimeoutErr):
		if err := enc.WriteToken(jsontext.String("owner")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(ownerLocal.String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("idle_timeout")); err != nil {
			return err
		}
	case errors.As(e.e, &applicationErr):
		owner := ownerLocal
		if applicationErr.Remote {
			owner = ownerRemote
		}
		if err := enc.WriteToken(jsontext.String("owner")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(owner.String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("application_code")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(applicationErr.ErrorCode))); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("reason")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(applicationErr.ErrorMessage)); err != nil {
			return err
		}
	case errors.As(e.e, &transportErr):
		owner := ownerLocal
		if transportErr.Remote {
			owner = ownerRemote
		}
		if err := enc.WriteToken(jsontext.String("owner")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(owner.String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("connection_code")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(transportError(transportErr.ErrorCode).String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("reason")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(transportErr.ErrorMessage)); err != nil {
			return err
		}
	case errors.As(e.e, &versionNegotiationErr):
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("version_mismatch")); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
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
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("raw")); err != nil {
		return err
	}
	if err := (rawInfo{Length: e.Length, PayloadLength: e.PayloadLength}).Encode(enc); err != nil {
		return err
	}
	if len(e.Frames) > 0 {
		if err := enc.WriteToken(jsontext.String("frames")); err != nil {
			return err
		}
		if err := e.Frames.Encode(enc); err != nil {
			return err
		}
	}
	if e.IsCoalesced {
		if err := enc.WriteToken(jsontext.String("is_coalesced")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
	}
	if e.ECN != logging.ECNUnsupported {
		if err := enc.WriteToken(jsontext.String("ecn")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(ecn(e.ECN).String())); err != nil {
			return err
		}
	}
	if e.Trigger != "" {
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(e.Trigger)); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
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
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("raw")); err != nil {
		return err
	}
	if err := (rawInfo{Length: e.Length, PayloadLength: e.PayloadLength}).Encode(enc); err != nil {
		return err
	}
	if len(e.Frames) > 0 {
		if err := enc.WriteToken(jsontext.String("frames")); err != nil {
			return err
		}
		if err := e.Frames.Encode(enc); err != nil {
			return err
		}
	}
	if e.IsCoalesced {
		if err := enc.WriteToken(jsontext.String("is_coalesced")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
	}
	if e.ECN != logging.ECNUnsupported {
		if err := enc.WriteToken(jsontext.String("ecn")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(ecn(e.ECN).String())); err != nil {
			return err
		}
	}
	if e.Trigger != "" {
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(e.Trigger)); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventRetryReceived struct {
	Header packetHeader
}

func (e eventRetryReceived) Name() string { return "transport:packet_received" }

func (e eventRetryReceived) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventVersionNegotiationReceived struct {
	Header            packetHeaderVersionNegotiation
	SupportedVersions []version
}

func (e eventVersionNegotiationReceived) Name() string { return "transport:packet_received" }

func (e eventVersionNegotiationReceived) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("supported_versions")); err != nil {
		return err
	}
	if err := versions(e.SupportedVersions).Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventVersionNegotiationSent struct {
	Header            packetHeaderVersionNegotiation
	SupportedVersions []version
}

func (e eventVersionNegotiationSent) Name() string { return "transport:packet_sent" }

func (e eventVersionNegotiationSent) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := e.Header.Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("supported_versions")); err != nil {
		return err
	}
	if err := versions(e.SupportedVersions).Encode(enc); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventPacketBuffered struct {
	PacketType logging.PacketType
	PacketSize protocol.ByteCount
}

func (e eventPacketBuffered) Name() string { return "transport:packet_buffered" }

func (e eventPacketBuffered) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := (packetHeaderWithType{
		PacketType:   e.PacketType,
		PacketNumber: protocol.InvalidPacketNumber,
	}).Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("raw")); err != nil {
		return err
	}
	if err := (rawInfo{Length: e.PacketSize}).Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("keys_unavailable")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventPacketDropped struct {
	PacketType   logging.PacketType
	PacketSize   protocol.ByteCount
	PacketNumber logging.PacketNumber
	Trigger      packetDropReason
}

func (e eventPacketDropped) Name() string { return "transport:packet_dropped" }

func (e eventPacketDropped) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := (packetHeaderWithType{
		PacketType:   e.PacketType,
		PacketNumber: e.PacketNumber,
	}.Encode(enc)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("raw")); err != nil {
		return err
	}
	if err := (rawInfo{Length: e.PacketSize}).Encode(enc); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.Trigger.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
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
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("mtu")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(e.mtu))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("done")); err != nil {
		return err
	}
	if e.done {
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
	} else {
		if err := enc.WriteToken(jsontext.False); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventMetricsUpdated struct {
	Last    *metrics
	Current *metrics
}

func (e eventMetricsUpdated) Name() string { return "recovery:metrics_updated" }

func (e eventMetricsUpdated) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if e.Last == nil || e.Last.MinRTT != e.Current.MinRTT {
		if err := enc.WriteToken(jsontext.String("min_rtt")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(e.Current.MinRTT))); err != nil {
			return err
		}
	}
	if e.Last == nil || e.Last.SmoothedRTT != e.Current.SmoothedRTT {
		if err := enc.WriteToken(jsontext.String("smoothed_rtt")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(e.Current.SmoothedRTT))); err != nil {
			return err
		}
	}
	if e.Last == nil || e.Last.LatestRTT != e.Current.LatestRTT {
		if err := enc.WriteToken(jsontext.String("latest_rtt")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(e.Current.LatestRTT))); err != nil {
			return err
		}
	}
	if e.Last == nil || e.Last.RTTVariance != e.Current.RTTVariance {
		if err := enc.WriteToken(jsontext.String("rtt_variance")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(e.Current.RTTVariance))); err != nil {
			return err
		}
	}
	if e.Last == nil || e.Last.CongestionWindow != e.Current.CongestionWindow {
		if err := enc.WriteToken(jsontext.String("congestion_window")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(e.Current.CongestionWindow))); err != nil {
			return err
		}
	}
	if e.Last == nil || e.Last.BytesInFlight != e.Current.BytesInFlight {
		if err := enc.WriteToken(jsontext.String("bytes_in_flight")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(e.Current.BytesInFlight))); err != nil {
			return err
		}
	}
	if e.Last == nil || e.Last.PacketsInFlight != e.Current.PacketsInFlight {
		if err := enc.WriteToken(jsontext.String("packets_in_flight")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(e.Current.PacketsInFlight))); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventUpdatedPTO struct {
	Value uint32
}

func (e eventUpdatedPTO) Name() string { return "recovery:metrics_updated" }

func (e eventUpdatedPTO) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("pto_count")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(e.Value))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventPacketLost struct {
	PacketType   logging.PacketType
	PacketNumber protocol.PacketNumber
	Trigger      packetLossReason
}

func (e eventPacketLost) Name() string { return "recovery:packet_lost" }

func (e eventPacketLost) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("header")); err != nil {
		return err
	}
	if err := (packetHeaderWithTypeAndPacketNumber{
		PacketType:   e.PacketType,
		PacketNumber: e.PacketNumber,
	}.Encode(enc)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.Trigger.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventSpuriousLoss struct {
	EncLevel     protocol.EncryptionLevel
	PacketNumber protocol.PacketNumber
	Reordering   uint64
	Duration     time.Duration
}

func (e eventSpuriousLoss) Name() string { return "recovery:spurious_loss" }

func (e eventSpuriousLoss) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_number_space")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_number")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(uint64(e.PacketNumber))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("reordering_packets")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Uint(e.Reordering)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("reordering_time")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Float(milliseconds(e.Duration))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventKeyUpdated struct {
	Trigger  keyUpdateTrigger
	KeyType  keyType
	KeyPhase protocol.KeyPhase
	// we don't log the keys here, so we don't need `old` and `new`.
}

func (e eventKeyUpdated) Name() string { return "security:key_updated" }

func (e eventKeyUpdated) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.Trigger.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("key_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.KeyType.String())); err != nil {
		return err
	}
	if e.KeyType == keyTypeClient1RTT || e.KeyType == keyTypeServer1RTT {
		if err := enc.WriteToken(jsontext.String("key_phase")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(e.KeyPhase))); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventKeyDiscarded struct {
	KeyType  keyType
	KeyPhase protocol.KeyPhase
}

func (e eventKeyDiscarded) Name() string { return "security:key_discarded" }

func (e eventKeyDiscarded) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if e.KeyType != keyTypeClient1RTT && e.KeyType != keyTypeServer1RTT {
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("tls")); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("key_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.KeyType.String())); err != nil {
		return err
	}
	if e.KeyType == keyTypeClient1RTT || e.KeyType == keyTypeServer1RTT {
		if err := enc.WriteToken(jsontext.String("key_phase")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(e.KeyPhase))); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
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
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if !e.Restore {
		if err := enc.WriteToken(jsontext.String("owner")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(e.Owner.String())); err != nil {
			return err
		}
		if e.SentBy == protocol.PerspectiveServer {
			if err := enc.WriteToken(jsontext.String("original_destination_connection_id")); err != nil {
				return err
			}
			if err := enc.WriteToken(jsontext.String(e.OriginalDestinationConnectionID.String())); err != nil {
				return err
			}
			if e.StatelessResetToken != nil {
				if err := enc.WriteToken(jsontext.String("stateless_reset_token")); err != nil {
					return err
				}
				if err := enc.WriteToken(jsontext.String(fmt.Sprintf("%x", e.StatelessResetToken[:]))); err != nil {
					return err
				}
			}
			if e.RetrySourceConnectionID != nil {
				if err := enc.WriteToken(jsontext.String("retry_source_connection_id")); err != nil {
					return err
				}
				if err := enc.WriteToken(jsontext.String((*e.RetrySourceConnectionID).String())); err != nil {
					return err
				}
			}
		}
		if err := enc.WriteToken(jsontext.String("initial_source_connection_id")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(e.InitialSourceConnectionID.String())); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("disable_active_migration")); err != nil {
		return err
	}
	if e.DisableActiveMigration {
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
	} else {
		if err := enc.WriteToken(jsontext.False); err != nil {
			return err
		}
	}
	if e.MaxIdleTimeout != 0 {
		if err := enc.WriteToken(jsontext.String("max_idle_timeout")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(e.MaxIdleTimeout))); err != nil {
			return err
		}
	}
	if e.MaxUDPPayloadSize != 0 {
		if err := enc.WriteToken(jsontext.String("max_udp_payload_size")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(e.MaxUDPPayloadSize))); err != nil {
			return err
		}
	}
	if e.AckDelayExponent != 0 {
		if err := enc.WriteToken(jsontext.String("ack_delay_exponent")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(e.AckDelayExponent))); err != nil {
			return err
		}
	}
	if e.MaxAckDelay != 0 {
		if err := enc.WriteToken(jsontext.String("max_ack_delay")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Float(milliseconds(e.MaxAckDelay))); err != nil {
			return err
		}
	}
	if e.ActiveConnectionIDLimit != 0 {
		if err := enc.WriteToken(jsontext.String("active_connection_id_limit")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(e.ActiveConnectionIDLimit)); err != nil {
			return err
		}
	}
	if e.InitialMaxData != 0 {
		if err := enc.WriteToken(jsontext.String("initial_max_data")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(e.InitialMaxData))); err != nil {
			return err
		}
	}
	if e.InitialMaxStreamDataBidiLocal != 0 {
		if err := enc.WriteToken(jsontext.String("initial_max_stream_data_bidi_local")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiLocal))); err != nil {
			return err
		}
	}
	if e.InitialMaxStreamDataBidiRemote != 0 {
		if err := enc.WriteToken(jsontext.String("initial_max_stream_data_bidi_remote")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiRemote))); err != nil {
			return err
		}
	}
	if e.InitialMaxStreamDataUni != 0 {
		if err := enc.WriteToken(jsontext.String("initial_max_stream_data_uni")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataUni))); err != nil {
			return err
		}
	}
	if e.InitialMaxStreamsBidi != 0 {
		if err := enc.WriteToken(jsontext.String("initial_max_streams_bidi")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(e.InitialMaxStreamsBidi)); err != nil {
			return err
		}
	}
	if e.InitialMaxStreamsUni != 0 {
		if err := enc.WriteToken(jsontext.String("initial_max_streams_uni")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(e.InitialMaxStreamsUni)); err != nil {
			return err
		}
	}
	if e.PreferredAddress != nil {
		if err := enc.WriteToken(jsontext.String("preferred_address")); err != nil {
			return err
		}
		if err := e.PreferredAddress.Encode(enc); err != nil {
			return err
		}
	}
	if e.MaxDatagramFrameSize != protocol.InvalidByteCount {
		if err := enc.WriteToken(jsontext.String("max_datagram_frame_size")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Int(int64(e.MaxDatagramFrameSize))); err != nil {
			return err
		}
	}
	if e.EnableResetStreamAt {
		if err := enc.WriteToken(jsontext.String("reset_stream_at")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.True); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type preferredAddress struct {
	IPv4, IPv6          netip.AddrPort
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func (a preferredAddress) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if a.IPv4.IsValid() {
		if err := enc.WriteToken(jsontext.String("ip_v4")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(a.IPv4.Addr().String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("port_v4")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(a.IPv4.Port()))); err != nil {
			return err
		}
	}
	if a.IPv6.IsValid() {
		if err := enc.WriteToken(jsontext.String("ip_v6")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(a.IPv6.Addr().String())); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String("port_v6")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Uint(uint64(a.IPv6.Port()))); err != nil {
			return err
		}
	}
	if err := enc.WriteToken(jsontext.String("connection_id")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(a.ConnectionID.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("stateless_reset_token")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(fmt.Sprintf("%x", a.StatelessResetToken))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventLossTimerSet struct {
	TimerType timerType
	EncLevel  protocol.EncryptionLevel
	Delta     time.Duration
}

func (e eventLossTimerSet) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerSet) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("event_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("set")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("timer_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.TimerType.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_number_space")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel))); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("delta")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Float(milliseconds(e.Delta))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventLossTimerExpired struct {
	TimerType timerType
	EncLevel  protocol.EncryptionLevel
}

func (e eventLossTimerExpired) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerExpired) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("event_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("expired")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("timer_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.TimerType.String())); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("packet_number_space")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel))); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventLossTimerCanceled struct{}

func (e eventLossTimerCanceled) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerCanceled) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("event_type")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("cancelled")); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventCongestionStateUpdated struct {
	state congestionState
}

func (e eventCongestionStateUpdated) Name() string { return "recovery:congestion_state_updated" }

func (e eventCongestionStateUpdated) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("new")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.state.String())); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventECNStateUpdated struct {
	state   logging.ECNState
	trigger logging.ECNStateTrigger
}

func (e eventECNStateUpdated) Name() string { return "recovery:ecn_state_updated" }

func (e eventECNStateUpdated) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("new")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(ecnState(e.state).String())); err != nil {
		return err
	}
	if e.trigger != 0 {
		if err := enc.WriteToken(jsontext.String("trigger")); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(ecnStateTrigger(e.trigger).String())); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventALPNInformation struct {
	chosenALPN string
}

func (e eventALPNInformation) Name() string { return "transport:alpn_information" }

func (e eventALPNInformation) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("chosen_alpn")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.chosenALPN)); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}

type eventGeneric struct {
	name string
	msg  string
}

func (e eventGeneric) Name() string { return "transport:" + e.name }

func (e eventGeneric) Encode(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String("details")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(e.msg)); err != nil {
		return err
	}
	return enc.WriteToken(jsontext.EndObject)
}
