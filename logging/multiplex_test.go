package logging

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Tracing", func() {
	Context("Tracer", func() {
		It("returns a nil tracer if no tracers are passed in", func() {
			Expect(NewMultiplexedTracer()).To(BeNil())
		})

		It("returns the raw tracer if only one tracer is passed in", func() {
			tr := NewMockTracer(mockCtrl)
			tracer := NewMultiplexedTracer(tr)
			Expect(tracer).To(BeAssignableToTypeOf(&MockTracer{}))
		})

		Context("tracing events", func() {
			var (
				tracer   Tracer
				tr1, tr2 *MockTracer
			)

			BeforeEach(func() {
				tr1 = NewMockTracer(mockCtrl)
				tr2 = NewMockTracer(mockCtrl)
				tracer = NewMultiplexedTracer(tr1, tr2)
			})

			It("multiplexes the TracerForConnection call", func() {
				ctx := context.Background()
				tr1.EXPECT().TracerForConnection(ctx, PerspectiveClient, ConnectionID{1, 2, 3})
				tr2.EXPECT().TracerForConnection(ctx, PerspectiveClient, ConnectionID{1, 2, 3})
				tracer.TracerForConnection(ctx, PerspectiveClient, ConnectionID{1, 2, 3})
			})

			It("uses multiple connection tracers", func() {
				ctx := context.Background()
				ctr1 := NewMockConnectionTracer(mockCtrl)
				ctr2 := NewMockConnectionTracer(mockCtrl)
				tr1.EXPECT().TracerForConnection(ctx, PerspectiveServer, ConnectionID{1, 2, 3}).Return(ctr1)
				tr2.EXPECT().TracerForConnection(ctx, PerspectiveServer, ConnectionID{1, 2, 3}).Return(ctr2)
				tr := tracer.TracerForConnection(ctx, PerspectiveServer, ConnectionID{1, 2, 3})
				ctr1.EXPECT().LossTimerCanceled()
				ctr2.EXPECT().LossTimerCanceled()
				tr.LossTimerCanceled()
			})

			It("handles tracers that return a nil ConnectionTracer", func() {
				ctx := context.Background()
				ctr1 := NewMockConnectionTracer(mockCtrl)
				tr1.EXPECT().TracerForConnection(ctx, PerspectiveServer, ConnectionID{1, 2, 3}).Return(ctr1)
				tr2.EXPECT().TracerForConnection(ctx, PerspectiveServer, ConnectionID{1, 2, 3})
				tr := tracer.TracerForConnection(ctx, PerspectiveServer, ConnectionID{1, 2, 3})
				ctr1.EXPECT().LossTimerCanceled()
				tr.LossTimerCanceled()
			})

			It("returns nil when all tracers return a nil ConnectionTracer", func() {
				ctx := context.Background()
				tr1.EXPECT().TracerForConnection(ctx, PerspectiveClient, ConnectionID{1, 2, 3})
				tr2.EXPECT().TracerForConnection(ctx, PerspectiveClient, ConnectionID{1, 2, 3})
				Expect(tracer.TracerForConnection(ctx, PerspectiveClient, ConnectionID{1, 2, 3})).To(BeNil())
			})

			It("traces the PacketSent event", func() {
				remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
				hdr := &Header{DestConnectionID: ConnectionID{1, 2, 3}}
				f := &MaxDataFrame{MaximumData: 1337}
				tr1.EXPECT().SentPacket(remote, hdr, ByteCount(1024), []Frame{f})
				tr2.EXPECT().SentPacket(remote, hdr, ByteCount(1024), []Frame{f})
				tracer.SentPacket(remote, hdr, 1024, []Frame{f})
			})

			It("traces the PacketDropped event", func() {
				remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
				tr1.EXPECT().DroppedPacket(remote, PacketTypeRetry, ByteCount(1024), PacketDropDuplicate)
				tr2.EXPECT().DroppedPacket(remote, PacketTypeRetry, ByteCount(1024), PacketDropDuplicate)
				tracer.DroppedPacket(remote, PacketTypeRetry, 1024, PacketDropDuplicate)
			})
		})
	})

	Context("Connection Tracer", func() {
		var (
			tracer ConnectionTracer
			tr1    *MockConnectionTracer
			tr2    *MockConnectionTracer
		)

		BeforeEach(func() {
			tr1 = NewMockConnectionTracer(mockCtrl)
			tr2 = NewMockConnectionTracer(mockCtrl)
			tracer = NewMultiplexedConnectionTracer(tr1, tr2)
		})

		It("trace the ConnectionStarted event", func() {
			local := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4)}
			remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
			tr1.EXPECT().StartedConnection(local, remote, ConnectionID{1, 2, 3, 4}, ConnectionID{4, 3, 2, 1})
			tr2.EXPECT().StartedConnection(local, remote, ConnectionID{1, 2, 3, 4}, ConnectionID{4, 3, 2, 1})
			tracer.StartedConnection(local, remote, ConnectionID{1, 2, 3, 4}, ConnectionID{4, 3, 2, 1})
		})

		It("traces the ClosedConnection event", func() {
			e := errors.New("test err")
			tr1.EXPECT().ClosedConnection(e)
			tr2.EXPECT().ClosedConnection(e)
			tracer.ClosedConnection(e)
		})

		It("traces the SentTransportParameters event", func() {
			tp := &wire.TransportParameters{InitialMaxData: 1337}
			tr1.EXPECT().SentTransportParameters(tp)
			tr2.EXPECT().SentTransportParameters(tp)
			tracer.SentTransportParameters(tp)
		})

		It("traces the ReceivedTransportParameters event", func() {
			tp := &wire.TransportParameters{InitialMaxData: 1337}
			tr1.EXPECT().ReceivedTransportParameters(tp)
			tr2.EXPECT().ReceivedTransportParameters(tp)
			tracer.ReceivedTransportParameters(tp)
		})

		It("traces the RestoredTransportParameters event", func() {
			tp := &wire.TransportParameters{InitialMaxData: 1337}
			tr1.EXPECT().RestoredTransportParameters(tp)
			tr2.EXPECT().RestoredTransportParameters(tp)
			tracer.RestoredTransportParameters(tp)
		})

		It("traces the SentPacket event", func() {
			hdr := &ExtendedHeader{Header: Header{DestConnectionID: ConnectionID{1, 2, 3}}}
			ack := &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 10}}}
			ping := &PingFrame{}
			tr1.EXPECT().SentPacket(hdr, ByteCount(1337), ack, []Frame{ping})
			tr2.EXPECT().SentPacket(hdr, ByteCount(1337), ack, []Frame{ping})
			tracer.SentPacket(hdr, 1337, ack, []Frame{ping})
		})

		It("traces the ReceivedVersionNegotiationPacket event", func() {
			hdr := &Header{DestConnectionID: ConnectionID{1, 2, 3}}
			tr1.EXPECT().ReceivedVersionNegotiationPacket(hdr, []VersionNumber{1337})
			tr2.EXPECT().ReceivedVersionNegotiationPacket(hdr, []VersionNumber{1337})
			tracer.ReceivedVersionNegotiationPacket(hdr, []VersionNumber{1337})
		})

		It("traces the ReceivedRetry event", func() {
			hdr := &Header{DestConnectionID: ConnectionID{1, 2, 3}}
			tr1.EXPECT().ReceivedRetry(hdr)
			tr2.EXPECT().ReceivedRetry(hdr)
			tracer.ReceivedRetry(hdr)
		})

		It("traces the ReceivedPacket event", func() {
			hdr := &ExtendedHeader{Header: Header{DestConnectionID: ConnectionID{1, 2, 3}}}
			ping := &PingFrame{}
			tr1.EXPECT().ReceivedPacket(hdr, ByteCount(1337), []Frame{ping})
			tr2.EXPECT().ReceivedPacket(hdr, ByteCount(1337), []Frame{ping})
			tracer.ReceivedPacket(hdr, 1337, []Frame{ping})
		})

		It("traces the BufferedPacket event", func() {
			tr1.EXPECT().BufferedPacket(PacketTypeHandshake)
			tr2.EXPECT().BufferedPacket(PacketTypeHandshake)
			tracer.BufferedPacket(PacketTypeHandshake)
		})

		It("traces the DroppedPacket event", func() {
			tr1.EXPECT().DroppedPacket(PacketTypeInitial, ByteCount(1337), PacketDropHeaderParseError)
			tr2.EXPECT().DroppedPacket(PacketTypeInitial, ByteCount(1337), PacketDropHeaderParseError)
			tracer.DroppedPacket(PacketTypeInitial, 1337, PacketDropHeaderParseError)
		})

		It("traces the UpdatedCongestionState event", func() {
			tr1.EXPECT().UpdatedCongestionState(CongestionStateRecovery)
			tr2.EXPECT().UpdatedCongestionState(CongestionStateRecovery)
			tracer.UpdatedCongestionState(CongestionStateRecovery)
		})

		It("traces the UpdatedMetrics event", func() {
			rttStats := &RTTStats{}
			rttStats.UpdateRTT(time.Second, 0, time.Now())
			tr1.EXPECT().UpdatedMetrics(rttStats, ByteCount(1337), ByteCount(42), 13)
			tr2.EXPECT().UpdatedMetrics(rttStats, ByteCount(1337), ByteCount(42), 13)
			tracer.UpdatedMetrics(rttStats, 1337, 42, 13)
		})

		It("traces the AcknowledgedPacket event", func() {
			tr1.EXPECT().AcknowledgedPacket(EncryptionHandshake, PacketNumber(42))
			tr2.EXPECT().AcknowledgedPacket(EncryptionHandshake, PacketNumber(42))
			tracer.AcknowledgedPacket(EncryptionHandshake, 42)
		})

		It("traces the LostPacket event", func() {
			tr1.EXPECT().LostPacket(EncryptionHandshake, PacketNumber(42), PacketLossReorderingThreshold)
			tr2.EXPECT().LostPacket(EncryptionHandshake, PacketNumber(42), PacketLossReorderingThreshold)
			tracer.LostPacket(EncryptionHandshake, 42, PacketLossReorderingThreshold)
		})

		It("traces the UpdatedPTOCount event", func() {
			tr1.EXPECT().UpdatedPTOCount(uint32(88))
			tr2.EXPECT().UpdatedPTOCount(uint32(88))
			tracer.UpdatedPTOCount(88)
		})

		It("traces the UpdatedKeyFromTLS event", func() {
			tr1.EXPECT().UpdatedKeyFromTLS(EncryptionHandshake, PerspectiveClient)
			tr2.EXPECT().UpdatedKeyFromTLS(EncryptionHandshake, PerspectiveClient)
			tracer.UpdatedKeyFromTLS(EncryptionHandshake, PerspectiveClient)
		})

		It("traces the UpdatedKey event", func() {
			tr1.EXPECT().UpdatedKey(KeyPhase(42), true)
			tr2.EXPECT().UpdatedKey(KeyPhase(42), true)
			tracer.UpdatedKey(KeyPhase(42), true)
		})

		It("traces the DroppedEncryptionLevel event", func() {
			tr1.EXPECT().DroppedEncryptionLevel(EncryptionHandshake)
			tr2.EXPECT().DroppedEncryptionLevel(EncryptionHandshake)
			tracer.DroppedEncryptionLevel(EncryptionHandshake)
		})

		It("traces the DroppedKey event", func() {
			tr1.EXPECT().DroppedKey(KeyPhase(123))
			tr2.EXPECT().DroppedKey(KeyPhase(123))
			tracer.DroppedKey(123)
		})

		It("traces the SetLossTimer event", func() {
			now := time.Now()
			tr1.EXPECT().SetLossTimer(TimerTypePTO, EncryptionHandshake, now)
			tr2.EXPECT().SetLossTimer(TimerTypePTO, EncryptionHandshake, now)
			tracer.SetLossTimer(TimerTypePTO, EncryptionHandshake, now)
		})

		It("traces the LossTimerExpired event", func() {
			tr1.EXPECT().LossTimerExpired(TimerTypePTO, EncryptionHandshake)
			tr2.EXPECT().LossTimerExpired(TimerTypePTO, EncryptionHandshake)
			tracer.LossTimerExpired(TimerTypePTO, EncryptionHandshake)
		})

		It("traces the LossTimerCanceled event", func() {
			tr1.EXPECT().LossTimerCanceled()
			tr2.EXPECT().LossTimerCanceled()
			tracer.LossTimerCanceled()
		})

		It("traces the Close event", func() {
			tr1.EXPECT().Close()
			tr2.EXPECT().Close()
			tracer.Close()
		})
	})
})
