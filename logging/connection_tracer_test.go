package logging_test

import (
	"errors"
	"net"
	"testing"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"go.uber.org/mock/gomock"
)

func TestConnectionTracerStartedConnection(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	local := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}
	remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
	dest := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	src := protocol.ParseConnectionID([]byte{4, 3, 2, 1})
	tr1.EXPECT().StartedConnection(local, remote, src, dest)
	tr2.EXPECT().StartedConnection(local, remote, src, dest)
	tracer.StartedConnection(local, remote, src, dest)
}

func TestConnectionTracerNegotiatedVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	chosen := protocol.Version2
	client := []protocol.Version{protocol.Version1}
	server := []protocol.Version{13, 37}
	tr1.EXPECT().NegotiatedVersion(chosen, client, server)
	tr2.EXPECT().NegotiatedVersion(chosen, client, server)
	tracer.NegotiatedVersion(chosen, client, server)
}

func TestConnectionTracerClosedConnection(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	e := errors.New("test err")
	tr1.EXPECT().ClosedConnection(e)
	tr2.EXPECT().ClosedConnection(e)
	tracer.ClosedConnection(e)
}

func TestConnectionTracerSentTransportParameters(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tp := &wire.TransportParameters{InitialMaxData: 1337}
	tr1.EXPECT().SentTransportParameters(tp)
	tr2.EXPECT().SentTransportParameters(tp)
	tracer.SentTransportParameters(tp)
}

func TestConnectionTracerReceivedTransportParameters(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tp := &wire.TransportParameters{InitialMaxData: 1337}
	tr1.EXPECT().ReceivedTransportParameters(tp)
	tr2.EXPECT().ReceivedTransportParameters(tp)
	tracer.ReceivedTransportParameters(tp)
}

func TestConnectionTracerRestoredTransportParameters(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tp := &wire.TransportParameters{InitialMaxData: 1337}
	tr1.EXPECT().RestoredTransportParameters(tp)
	tr2.EXPECT().RestoredTransportParameters(tp)
	tracer.RestoredTransportParameters(tp)
}

func TestConnectionTracerSentLongHeaderPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	hdr := &logging.ExtendedHeader{Header: logging.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}}
	ack := &logging.AckFrame{AckRanges: []logging.AckRange{{Smallest: 1, Largest: 10}}}
	ping := &logging.PingFrame{}
	tr1.EXPECT().SentLongHeaderPacket(hdr, logging.ByteCount(1337), logging.ECTNot, ack, []logging.Frame{ping})
	tr2.EXPECT().SentLongHeaderPacket(hdr, logging.ByteCount(1337), logging.ECTNot, ack, []logging.Frame{ping})
	tracer.SentLongHeaderPacket(hdr, 1337, logging.ECTNot, ack, []logging.Frame{ping})
}

func TestConnectionTracerSentShortHeaderPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	hdr := &logging.ShortHeader{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}
	ack := &logging.AckFrame{AckRanges: []logging.AckRange{{Smallest: 1, Largest: 10}}}
	ping := &logging.PingFrame{}
	tr1.EXPECT().SentShortHeaderPacket(hdr, logging.ByteCount(1337), logging.ECNCE, ack, []logging.Frame{ping})
	tr2.EXPECT().SentShortHeaderPacket(hdr, logging.ByteCount(1337), logging.ECNCE, ack, []logging.Frame{ping})
	tracer.SentShortHeaderPacket(hdr, 1337, logging.ECNCE, ack, []logging.Frame{ping})
}

func TestConnectionTracerReceivedVersionNegotiationPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	src := logging.ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	dest := logging.ArbitraryLenConnectionID{1, 2, 3, 4}
	tr1.EXPECT().ReceivedVersionNegotiationPacket(dest, src, []logging.Version{1337})
	tr2.EXPECT().ReceivedVersionNegotiationPacket(dest, src, []logging.Version{1337})
	tracer.ReceivedVersionNegotiationPacket(dest, src, []logging.Version{1337})
}

func TestConnectionTracerReceivedRetry(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	hdr := &logging.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}
	tr1.EXPECT().ReceivedRetry(hdr)
	tr2.EXPECT().ReceivedRetry(hdr)
	tracer.ReceivedRetry(hdr)
}

func TestConnectionTracerReceivedLongHeaderPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	hdr := &logging.ExtendedHeader{Header: logging.Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}}
	ping := &logging.PingFrame{}
	tr1.EXPECT().ReceivedLongHeaderPacket(hdr, logging.ByteCount(1337), logging.ECT1, []logging.Frame{ping})
	tr2.EXPECT().ReceivedLongHeaderPacket(hdr, logging.ByteCount(1337), logging.ECT1, []logging.Frame{ping})
	tracer.ReceivedLongHeaderPacket(hdr, 1337, logging.ECT1, []logging.Frame{ping})
}

func TestConnectionTracerReceivedShortHeaderPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	hdr := &logging.ShortHeader{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}
	ping := &logging.PingFrame{}
	tr1.EXPECT().ReceivedShortHeaderPacket(hdr, logging.ByteCount(1337), logging.ECT0, []logging.Frame{ping})
	tr2.EXPECT().ReceivedShortHeaderPacket(hdr, logging.ByteCount(1337), logging.ECT0, []logging.Frame{ping})
	tracer.ReceivedShortHeaderPacket(hdr, 1337, logging.ECT0, []logging.Frame{ping})
}

func TestConnectionTracerBufferedPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().BufferedPacket(logging.PacketTypeHandshake, logging.ByteCount(1337))
	tr2.EXPECT().BufferedPacket(logging.PacketTypeHandshake, logging.ByteCount(1337))
	tracer.BufferedPacket(logging.PacketTypeHandshake, 1337)
}

func TestConnectionTracerDroppedPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().DroppedPacket(logging.PacketTypeInitial, logging.PacketNumber(42), logging.ByteCount(1337), logging.PacketDropHeaderParseError)
	tr2.EXPECT().DroppedPacket(logging.PacketTypeInitial, logging.PacketNumber(42), logging.ByteCount(1337), logging.PacketDropHeaderParseError)
	tracer.DroppedPacket(logging.PacketTypeInitial, 42, 1337, logging.PacketDropHeaderParseError)
}

func TestConnectionTracerUpdatedMTU(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().UpdatedMTU(logging.ByteCount(1337), true)
	tr2.EXPECT().UpdatedMTU(logging.ByteCount(1337), true)
	tracer.UpdatedMTU(1337, true)
}

func TestConnectionTracerUpdatedCongestionState(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().UpdatedCongestionState(logging.CongestionStateRecovery)
	tr2.EXPECT().UpdatedCongestionState(logging.CongestionStateRecovery)
	tracer.UpdatedCongestionState(logging.CongestionStateRecovery)
}

func TestConnectionTracerUpdatedMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	rttStats := &logging.RTTStats{}
	rttStats.UpdateRTT(time.Second, 0, time.Now())
	tr1.EXPECT().UpdatedMetrics(rttStats, logging.ByteCount(1337), logging.ByteCount(42), 13)
	tr2.EXPECT().UpdatedMetrics(rttStats, logging.ByteCount(1337), logging.ByteCount(42), 13)
	tracer.UpdatedMetrics(rttStats, 1337, 42, 13)
}

func TestConnectionTracerAcknowledgedPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().AcknowledgedPacket(logging.EncryptionHandshake, logging.PacketNumber(42))
	tr2.EXPECT().AcknowledgedPacket(logging.EncryptionHandshake, logging.PacketNumber(42))
	tracer.AcknowledgedPacket(logging.EncryptionHandshake, 42)
}

func TestConnectionTracerLostPacket(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().LostPacket(logging.EncryptionHandshake, logging.PacketNumber(42), logging.PacketLossReorderingThreshold)
	tr2.EXPECT().LostPacket(logging.EncryptionHandshake, logging.PacketNumber(42), logging.PacketLossReorderingThreshold)
	tracer.LostPacket(logging.EncryptionHandshake, 42, logging.PacketLossReorderingThreshold)
}

func TestConnectionTracerUpdatedPTOCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().UpdatedPTOCount(uint32(88))
	tr2.EXPECT().UpdatedPTOCount(uint32(88))
	tracer.UpdatedPTOCount(88)
}

func TestConnectionTracerUpdatedKeyFromTLS(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().UpdatedKeyFromTLS(logging.EncryptionHandshake, logging.PerspectiveClient)
	tr2.EXPECT().UpdatedKeyFromTLS(logging.EncryptionHandshake, logging.PerspectiveClient)
	tracer.UpdatedKeyFromTLS(logging.EncryptionHandshake, logging.PerspectiveClient)
}

func TestConnectionTracerUpdatedKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().UpdatedKey(logging.KeyPhase(42), true)
	tr2.EXPECT().UpdatedKey(logging.KeyPhase(42), true)
	tracer.UpdatedKey(logging.KeyPhase(42), true)
}

func TestConnectionTracerDroppedEncryptionLevel(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().DroppedEncryptionLevel(logging.EncryptionHandshake)
	tr2.EXPECT().DroppedEncryptionLevel(logging.EncryptionHandshake)
	tracer.DroppedEncryptionLevel(logging.EncryptionHandshake)
}

func TestConnectionTracerDroppedKey(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().DroppedKey(logging.KeyPhase(123))
	tr2.EXPECT().DroppedKey(logging.KeyPhase(123))
	tracer.DroppedKey(123)
}

func TestConnectionTracerSetLossTimer(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	now := time.Now()
	tr1.EXPECT().SetLossTimer(logging.TimerTypePTO, logging.EncryptionHandshake, now)
	tr2.EXPECT().SetLossTimer(logging.TimerTypePTO, logging.EncryptionHandshake, now)
	tracer.SetLossTimer(logging.TimerTypePTO, logging.EncryptionHandshake, now)
}

func TestConnectionTracerLossTimerExpired(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().LossTimerExpired(logging.TimerTypePTO, logging.EncryptionHandshake)
	tr2.EXPECT().LossTimerExpired(logging.TimerTypePTO, logging.EncryptionHandshake)
	tracer.LossTimerExpired(logging.TimerTypePTO, logging.EncryptionHandshake)
}

func TestConnectionTracerLossTimerCanceled(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().LossTimerCanceled()
	tr2.EXPECT().LossTimerCanceled()
	tracer.LossTimerCanceled()
}

func TestConnectionTracerClose(t *testing.T) {
	ctrl := gomock.NewController(t)
	t1, tr1 := mocklogging.NewMockConnectionTracer(ctrl)
	t2, tr2 := mocklogging.NewMockConnectionTracer(ctrl)
	tracer := logging.NewMultiplexedConnectionTracer(t1, t2)

	tr1.EXPECT().Close()
	tr2.EXPECT().Close()
	tracer.Close()
}
