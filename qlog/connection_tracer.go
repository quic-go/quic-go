package qlog

import (
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/francoispqt/gojay"
)

type connectionTracer struct {
	w           writer
	lastMetrics *metrics

	perspective logging.Perspective
}

// NewConnectionTracer creates a new tracer to record a qlog for a connection.
func NewConnectionTracer(w io.WriteCloser, p logging.Perspective, odcid protocol.ConnectionID) *logging.ConnectionTracer {
	tr := &trace{
		VantagePoint: vantagePoint{Type: p.String()},
		CommonFields: commonFields{
			ODCID:         &odcid,
			GroupID:       &odcid,
			ReferenceTime: time.Now(),
		},
	}
	t := connectionTracer{
		w:           *newWriter(w, tr),
		perspective: p,
	}
	go t.w.Run()
	return &logging.ConnectionTracer{
		StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
			t.StartedConnection(local, remote, srcConnID, destConnID)
		},
		NegotiatedVersion: func(chosen logging.Version, clientVersions, serverVersions []logging.Version) {
			t.NegotiatedVersion(chosen, clientVersions, serverVersions)
		},
		ClosedConnection:            func(e error) { t.ClosedConnection(e) },
		SentTransportParameters:     func(tp *wire.TransportParameters) { t.SentTransportParameters(tp) },
		ReceivedTransportParameters: func(tp *wire.TransportParameters) { t.ReceivedTransportParameters(tp) },
		RestoredTransportParameters: func(tp *wire.TransportParameters) { t.RestoredTransportParameters(tp) },
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.SentLongHeaderPacket(hdr, size, ecn, ack, frames)
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.SentShortHeaderPacket(hdr, size, ecn, ack, frames)
		},
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.ReceivedLongHeaderPacket(hdr, size, ecn, frames)
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.ReceivedShortHeaderPacket(hdr, size, ecn, frames)
		},
		ReceivedRetry: func(hdr *wire.Header) {
			t.ReceivedRetry(hdr)
		},
		ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, versions []logging.Version) {
			t.ReceivedVersionNegotiationPacket(dest, src, versions)
		},
		BufferedPacket: func(pt logging.PacketType, size protocol.ByteCount) {
			t.BufferedPacket(pt, size)
		},
		DroppedPacket: func(pt logging.PacketType, pn logging.PacketNumber, size logging.ByteCount, reason logging.PacketDropReason) {
			t.DroppedPacket(pt, pn, size, reason)
		},
		UpdatedMetrics: func(rttStats *utils.RTTStats, cwnd, bytesInFlight protocol.ByteCount, packetsInFlight int) {
			t.UpdatedMetrics(rttStats, cwnd, bytesInFlight, packetsInFlight)
		},
		LostPacket: func(encLevel protocol.EncryptionLevel, pn protocol.PacketNumber, lossReason logging.PacketLossReason) {
			t.LostPacket(encLevel, pn, lossReason)
		},
		UpdatedMTU: func(mtu logging.ByteCount, done bool) {
			t.UpdatedMTU(mtu, done)
		},
		UpdatedCongestionState: func(state logging.CongestionState) {
			t.UpdatedCongestionState(state)
		},
		UpdatedPTOCount: func(value uint32) {
			t.UpdatedPTOCount(value)
		},
		UpdatedKeyFromTLS: func(encLevel protocol.EncryptionLevel, pers protocol.Perspective) {
			t.UpdatedKeyFromTLS(encLevel, pers)
		},
		UpdatedKey: func(keyPhase protocol.KeyPhase, remote bool) {
			t.UpdatedKey(keyPhase, remote)
		},
		DroppedEncryptionLevel: func(encLevel protocol.EncryptionLevel) {
			t.DroppedEncryptionLevel(encLevel)
		},
		DroppedKey: func(keyPhase protocol.KeyPhase) {
			t.DroppedKey(keyPhase)
		},
		SetLossTimer: func(tt logging.TimerType, encLevel protocol.EncryptionLevel, timeout time.Time) {
			t.SetLossTimer(tt, encLevel, timeout)
		},
		LossTimerExpired: func(tt logging.TimerType, encLevel protocol.EncryptionLevel) {
			t.LossTimerExpired(tt, encLevel)
		},
		LossTimerCanceled: func() {
			t.LossTimerCanceled()
		},
		ECNStateUpdated: func(state logging.ECNState, trigger logging.ECNStateTrigger) {
			t.ECNStateUpdated(state, trigger)
		},
		ChoseALPN: func(protocol string) {
			t.recordEvent(time.Now(), eventALPNInformation{chosenALPN: protocol})
		},
		Debug: func(name, msg string) {
			t.Debug(name, msg)
		},
		Close: func() {
			t.Close()
		},
	}
}

func (t *connectionTracer) recordEvent(eventTime time.Time, details eventDetails) {
	t.w.RecordEvent(eventTime, details)
}

func (t *connectionTracer) Close() {
	t.w.Close()
}

func (t *connectionTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID protocol.ConnectionID) {
	// ignore this event if we're not dealing with UDP addresses here
	localAddr, ok := local.(*net.UDPAddr)
	if !ok {
		return
	}
	remoteAddr, ok := remote.(*net.UDPAddr)
	if !ok {
		return
	}
	t.recordEvent(time.Now(), &eventConnectionStarted{
		SrcAddr:          localAddr,
		DestAddr:         remoteAddr,
		SrcConnectionID:  srcConnID,
		DestConnectionID: destConnID,
	})
}

func (t *connectionTracer) NegotiatedVersion(chosen logging.Version, client, server []logging.Version) {
	var clientVersions, serverVersions []version
	if len(client) > 0 {
		clientVersions = make([]version, len(client))
		for i, v := range client {
			clientVersions[i] = version(v)
		}
	}
	if len(server) > 0 {
		serverVersions = make([]version, len(server))
		for i, v := range server {
			serverVersions[i] = version(v)
		}
	}
	t.recordEvent(time.Now(), &eventVersionNegotiated{
		clientVersions: clientVersions,
		serverVersions: serverVersions,
		chosenVersion:  version(chosen),
	})
}

func (t *connectionTracer) ClosedConnection(e error) {
	t.recordEvent(time.Now(), &eventConnectionClosed{e: e})
}

func (t *connectionTracer) SentTransportParameters(tp *wire.TransportParameters) {
	t.recordTransportParameters(t.perspective, tp)
}

func (t *connectionTracer) ReceivedTransportParameters(tp *wire.TransportParameters) {
	t.recordTransportParameters(t.perspective.Opposite(), tp)
}

func (t *connectionTracer) RestoredTransportParameters(tp *wire.TransportParameters) {
	ev := t.toTransportParameters(tp)
	ev.Restore = true

	t.recordEvent(time.Now(), ev)
}

func (t *connectionTracer) recordTransportParameters(sentBy protocol.Perspective, tp *wire.TransportParameters) {
	ev := t.toTransportParameters(tp)
	ev.Owner = ownerLocal
	if sentBy != t.perspective {
		ev.Owner = ownerRemote
	}
	ev.SentBy = sentBy

	t.recordEvent(time.Now(), ev)
}

func (t *connectionTracer) toTransportParameters(tp *wire.TransportParameters) *eventTransportParameters {
	var pa *preferredAddress
	if tp.PreferredAddress != nil {
		pa = &preferredAddress{
			IPv4:                tp.PreferredAddress.IPv4,
			IPv6:                tp.PreferredAddress.IPv6,
			ConnectionID:        tp.PreferredAddress.ConnectionID,
			StatelessResetToken: tp.PreferredAddress.StatelessResetToken,
		}
	}
	return &eventTransportParameters{
		OriginalDestinationConnectionID: tp.OriginalDestinationConnectionID,
		InitialSourceConnectionID:       tp.InitialSourceConnectionID,
		RetrySourceConnectionID:         tp.RetrySourceConnectionID,
		StatelessResetToken:             tp.StatelessResetToken,
		DisableActiveMigration:          tp.DisableActiveMigration,
		MaxIdleTimeout:                  tp.MaxIdleTimeout,
		MaxUDPPayloadSize:               tp.MaxUDPPayloadSize,
		AckDelayExponent:                tp.AckDelayExponent,
		MaxAckDelay:                     tp.MaxAckDelay,
		ActiveConnectionIDLimit:         tp.ActiveConnectionIDLimit,
		InitialMaxData:                  tp.InitialMaxData,
		InitialMaxStreamDataBidiLocal:   tp.InitialMaxStreamDataBidiLocal,
		InitialMaxStreamDataBidiRemote:  tp.InitialMaxStreamDataBidiRemote,
		InitialMaxStreamDataUni:         tp.InitialMaxStreamDataUni,
		InitialMaxStreamsBidi:           int64(tp.MaxBidiStreamNum),
		InitialMaxStreamsUni:            int64(tp.MaxUniStreamNum),
		PreferredAddress:                pa,
		MaxDatagramFrameSize:            tp.MaxDatagramFrameSize,
	}
}

func (t *connectionTracer) SentLongHeaderPacket(
	hdr *logging.ExtendedHeader,
	size logging.ByteCount,
	ecn logging.ECN,
	ack *logging.AckFrame,
	frames []logging.Frame,
) {
	t.sentPacket(*transformLongHeader(hdr), size, hdr.Length, ecn, ack, frames)
}

func (t *connectionTracer) SentShortHeaderPacket(
	hdr *logging.ShortHeader,
	size logging.ByteCount,
	ecn logging.ECN,
	ack *logging.AckFrame,
	frames []logging.Frame,
) {
	t.sentPacket(*transformShortHeader(hdr), size, 0, ecn, ack, frames)
}

func (t *connectionTracer) sentPacket(
	hdr gojay.MarshalerJSONObject,
	size, payloadLen logging.ByteCount,
	ecn logging.ECN,
	ack *logging.AckFrame,
	frames []logging.Frame,
) {
	numFrames := len(frames)
	if ack != nil {
		numFrames++
	}
	fs := make([]frame, 0, numFrames)
	if ack != nil {
		fs = append(fs, frame{Frame: ack})
	}
	for _, f := range frames {
		fs = append(fs, frame{Frame: f})
	}
	t.recordEvent(time.Now(), &eventPacketSent{
		Header:        hdr,
		Length:        size,
		PayloadLength: payloadLen,
		ECN:           ecn,
		Frames:        fs,
	})
}

func (t *connectionTracer) ReceivedLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
	fs := make([]frame, len(frames))
	for i, f := range frames {
		fs[i] = frame{Frame: f}
	}
	header := *transformLongHeader(hdr)
	t.recordEvent(time.Now(), &eventPacketReceived{
		Header:        header,
		Length:        size,
		PayloadLength: hdr.Length,
		ECN:           ecn,
		Frames:        fs,
	})
}

func (t *connectionTracer) ReceivedShortHeaderPacket(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
	fs := make([]frame, len(frames))
	for i, f := range frames {
		fs[i] = frame{Frame: f}
	}
	header := *transformShortHeader(hdr)
	t.recordEvent(time.Now(), &eventPacketReceived{
		Header:        header,
		Length:        size,
		PayloadLength: size - wire.ShortHeaderLen(hdr.DestConnectionID, hdr.PacketNumberLen),
		ECN:           ecn,
		Frames:        fs,
	})
}

func (t *connectionTracer) ReceivedRetry(hdr *wire.Header) {
	t.recordEvent(time.Now(), &eventRetryReceived{
		Header: *transformHeader(hdr),
	})
}

func (t *connectionTracer) ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, versions []logging.Version) {
	ver := make([]version, len(versions))
	for i, v := range versions {
		ver[i] = version(v)
	}
	t.recordEvent(time.Now(), &eventVersionNegotiationReceived{
		Header: packetHeaderVersionNegotiation{
			SrcConnectionID:  src,
			DestConnectionID: dest,
		},
		SupportedVersions: ver,
	})
}

func (t *connectionTracer) BufferedPacket(pt logging.PacketType, size protocol.ByteCount) {
	t.recordEvent(time.Now(), &eventPacketBuffered{
		PacketType: pt,
		PacketSize: size,
	})
}

func (t *connectionTracer) DroppedPacket(pt logging.PacketType, pn logging.PacketNumber, size protocol.ByteCount, reason logging.PacketDropReason) {
	t.recordEvent(time.Now(), &eventPacketDropped{
		PacketType:   pt,
		PacketNumber: pn,
		PacketSize:   size,
		Trigger:      packetDropReason(reason),
	})
}

func (t *connectionTracer) UpdatedMetrics(rttStats *utils.RTTStats, cwnd, bytesInFlight protocol.ByteCount, packetsInFlight int) {
	m := &metrics{
		MinRTT:           rttStats.MinRTT(),
		SmoothedRTT:      rttStats.SmoothedRTT(),
		LatestRTT:        rttStats.LatestRTT(),
		RTTVariance:      rttStats.MeanDeviation(),
		CongestionWindow: cwnd,
		BytesInFlight:    bytesInFlight,
		PacketsInFlight:  packetsInFlight,
	}
	t.recordEvent(time.Now(), &eventMetricsUpdated{
		Last:    t.lastMetrics,
		Current: m,
	})
	t.lastMetrics = m
}

func (t *connectionTracer) AcknowledgedPacket(protocol.EncryptionLevel, protocol.PacketNumber) {}

func (t *connectionTracer) LostPacket(encLevel protocol.EncryptionLevel, pn protocol.PacketNumber, lossReason logging.PacketLossReason) {
	t.recordEvent(time.Now(), &eventPacketLost{
		PacketType:   getPacketTypeFromEncryptionLevel(encLevel),
		PacketNumber: pn,
		Trigger:      packetLossReason(lossReason),
	})
}

func (t *connectionTracer) UpdatedMTU(mtu protocol.ByteCount, done bool) {
	t.recordEvent(time.Now(), &eventMTUUpdated{mtu: mtu, done: done})
}

func (t *connectionTracer) UpdatedCongestionState(state logging.CongestionState) {
	t.recordEvent(time.Now(), &eventCongestionStateUpdated{state: congestionState(state)})
}

func (t *connectionTracer) UpdatedPTOCount(value uint32) {
	t.recordEvent(time.Now(), &eventUpdatedPTO{Value: value})
}

func (t *connectionTracer) UpdatedKeyFromTLS(encLevel protocol.EncryptionLevel, pers protocol.Perspective) {
	t.recordEvent(time.Now(), &eventKeyUpdated{
		Trigger: keyUpdateTLS,
		KeyType: encLevelToKeyType(encLevel, pers),
	})
}

func (t *connectionTracer) UpdatedKey(generation protocol.KeyPhase, remote bool) {
	trigger := keyUpdateLocal
	if remote {
		trigger = keyUpdateRemote
	}
	now := time.Now()
	t.recordEvent(now, &eventKeyUpdated{
		Trigger:  trigger,
		KeyType:  keyTypeClient1RTT,
		KeyPhase: generation,
	})
	t.recordEvent(now, &eventKeyUpdated{
		Trigger:  trigger,
		KeyType:  keyTypeServer1RTT,
		KeyPhase: generation,
	})
}

func (t *connectionTracer) DroppedEncryptionLevel(encLevel protocol.EncryptionLevel) {
	now := time.Now()
	if encLevel == protocol.Encryption0RTT {
		t.recordEvent(now, &eventKeyDiscarded{KeyType: encLevelToKeyType(encLevel, t.perspective)})
	} else {
		t.recordEvent(now, &eventKeyDiscarded{KeyType: encLevelToKeyType(encLevel, protocol.PerspectiveServer)})
		t.recordEvent(now, &eventKeyDiscarded{KeyType: encLevelToKeyType(encLevel, protocol.PerspectiveClient)})
	}
}

func (t *connectionTracer) DroppedKey(generation protocol.KeyPhase) {
	now := time.Now()
	t.recordEvent(now, &eventKeyDiscarded{
		KeyType:  encLevelToKeyType(protocol.Encryption1RTT, protocol.PerspectiveServer),
		KeyPhase: generation,
	})
	t.recordEvent(now, &eventKeyDiscarded{
		KeyType:  encLevelToKeyType(protocol.Encryption1RTT, protocol.PerspectiveClient),
		KeyPhase: generation,
	})
}

func (t *connectionTracer) SetLossTimer(tt logging.TimerType, encLevel protocol.EncryptionLevel, timeout time.Time) {
	now := time.Now()
	t.recordEvent(now, &eventLossTimerSet{
		TimerType: timerType(tt),
		EncLevel:  encLevel,
		Delta:     timeout.Sub(now),
	})
}

func (t *connectionTracer) LossTimerExpired(tt logging.TimerType, encLevel protocol.EncryptionLevel) {
	t.recordEvent(time.Now(), &eventLossTimerExpired{
		TimerType: timerType(tt),
		EncLevel:  encLevel,
	})
}

func (t *connectionTracer) LossTimerCanceled() {
	t.recordEvent(time.Now(), &eventLossTimerCanceled{})
}

func (t *connectionTracer) ECNStateUpdated(state logging.ECNState, trigger logging.ECNStateTrigger) {
	t.recordEvent(time.Now(), &eventECNStateUpdated{state: state, trigger: trigger})
}

func (t *connectionTracer) Debug(name, msg string) {
	t.recordEvent(time.Now(), &eventGeneric{
		name: name,
		msg:  msg,
	})
}
