//go:build !gomock && !generate

package mocklogging

import (
	"net"
	"time"

	"github.com/quic-go/quic-go/internal/mocks/logging/internal"
	"github.com/quic-go/quic-go/logging"

	"go.uber.org/mock/gomock"
)

type MockConnectionTracer = internal.MockConnectionTracer

func NewMockConnectionTracer(ctrl *gomock.Controller) (*logging.ConnectionTracer, *MockConnectionTracer) {
	t := internal.NewMockConnectionTracer(ctrl)
	return &logging.ConnectionTracer{
		StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
			t.StartedConnection(local, remote, srcConnID, destConnID)
		},
		NegotiatedVersion: func(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
			t.NegotiatedVersion(chosen, clientVersions, serverVersions)
		},
		ClosedConnection: func(e error) {
			t.ClosedConnection(e)
		},
		SentTransportParameters: func(tp *logging.TransportParameters) {
			t.SentTransportParameters(tp)
		},
		ReceivedTransportParameters: func(tp *logging.TransportParameters) {
			t.ReceivedTransportParameters(tp)
		},
		RestoredTransportParameters: func(tp *logging.TransportParameters) {
			t.RestoredTransportParameters(tp)
		},
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.SentLongHeaderPacket(hdr, size, ecn, ack, frames)
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
			t.SentShortHeaderPacket(hdr, size, ecn, ack, frames)
		},
		ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, versions []logging.VersionNumber) {
			t.ReceivedVersionNegotiationPacket(dest, src, versions)
		},
		ReceivedRetry: func(hdr *logging.Header) {
			t.ReceivedRetry(hdr)
		},
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.ReceivedLongHeaderPacket(hdr, size, ecn, frames)
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
			t.ReceivedShortHeaderPacket(hdr, size, ecn, frames)
		},
		BufferedPacket: func(typ logging.PacketType, size logging.ByteCount) {
			t.BufferedPacket(typ, size)
		},
		DroppedPacket: func(typ logging.PacketType, size logging.ByteCount, reason logging.PacketDropReason) {
			t.DroppedPacket(typ, size, reason)
		},
		UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
			t.UpdatedMetrics(rttStats, cwnd, bytesInFlight, packetsInFlight)
		},
		AcknowledgedPacket: func(encLevel logging.EncryptionLevel, pn logging.PacketNumber) {
			t.AcknowledgedPacket(encLevel, pn)
		},
		LostPacket: func(encLevel logging.EncryptionLevel, pn logging.PacketNumber, reason logging.PacketLossReason) {
			t.LostPacket(encLevel, pn, reason)
		},
		UpdatedCongestionState: func(state logging.CongestionState) {
			t.UpdatedCongestionState(state)
		},
		UpdatedPTOCount: func(value uint32) {
			t.UpdatedPTOCount(value)
		},
		UpdatedKeyFromTLS: func(encLevel logging.EncryptionLevel, perspective logging.Perspective) {
			t.UpdatedKeyFromTLS(encLevel, perspective)
		},
		UpdatedKey: func(generation logging.KeyPhase, remote bool) {
			t.UpdatedKey(generation, remote)
		},
		DroppedEncryptionLevel: func(encLevel logging.EncryptionLevel) {
			t.DroppedEncryptionLevel(encLevel)
		},
		DroppedKey: func(generation logging.KeyPhase) {
			t.DroppedKey(generation)
		},
		SetLossTimer: func(typ logging.TimerType, encLevel logging.EncryptionLevel, exp time.Time) {
			t.SetLossTimer(typ, encLevel, exp)
		},
		LossTimerExpired: func(typ logging.TimerType, encLevel logging.EncryptionLevel) {
			t.LossTimerExpired(typ, encLevel)
		},
		LossTimerCanceled: func() {
			t.LossTimerCanceled()
		},
		ECNStateUpdated: func(state logging.ECNState, trigger logging.ECNStateTrigger) {
			t.ECNStateUpdated(state, trigger)
		},
		Close: func() {
			t.Close()
		},
		Debug: func(name, msg string) {
			t.Debug(name, msg)
		},
	}, t
}
