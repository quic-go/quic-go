package logging_test

import (
	"net"
	"testing"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	. "github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNilTracerWhenEmpty(t *testing.T) {
	require.Nil(t, NewMultiplexedTracer())
}

func TestSingleTracer(t *testing.T) {
	tr := &Tracer{}
	tracer := NewMultiplexedTracer(tr)
	require.Equal(t, tr, tracer)
}

func TestTracerPacketSent(t *testing.T) {
	ctrl := gomock.NewController(t)

	t1, tr1 := mocklogging.NewMockTracer(ctrl)
	t2, tr2 := mocklogging.NewMockTracer(ctrl)
	tracer := NewMultiplexedTracer(t1, t2, &Tracer{})

	remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
	hdr := &Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}
	f := &MaxDataFrame{MaximumData: 1337}
	tr1.EXPECT().SentPacket(remote, hdr, ByteCount(1024), []Frame{f})
	tr2.EXPECT().SentPacket(remote, hdr, ByteCount(1024), []Frame{f})
	tracer.SentPacket(remote, hdr, 1024, []Frame{f})
}

func TestTracerVersionNegotiationSent(t *testing.T) {
	ctrl := gomock.NewController(t)

	t1, tr1 := mocklogging.NewMockTracer(ctrl)
	t2, tr2 := mocklogging.NewMockTracer(ctrl)
	tracer := NewMultiplexedTracer(t1, t2, &Tracer{})

	remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
	src := ArbitraryLenConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	dest := ArbitraryLenConnectionID{1, 2, 3, 4}
	versions := []Version{1, 2, 3}
	tr1.EXPECT().SentVersionNegotiationPacket(remote, dest, src, versions)
	tr2.EXPECT().SentVersionNegotiationPacket(remote, dest, src, versions)
	tracer.SentVersionNegotiationPacket(remote, dest, src, versions)
}

func TestTracerPacketDropped(t *testing.T) {
	ctrl := gomock.NewController(t)

	t1, tr1 := mocklogging.NewMockTracer(ctrl)
	t2, tr2 := mocklogging.NewMockTracer(ctrl)
	tracer := NewMultiplexedTracer(t1, t2, &Tracer{})

	remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
	tr1.EXPECT().DroppedPacket(remote, PacketTypeRetry, ByteCount(1024), PacketDropDuplicate)
	tr2.EXPECT().DroppedPacket(remote, PacketTypeRetry, ByteCount(1024), PacketDropDuplicate)
	tracer.DroppedPacket(remote, PacketTypeRetry, 1024, PacketDropDuplicate)
}

func TestTracerDebug(t *testing.T) {
	ctrl := gomock.NewController(t)

	t1, tr1 := mocklogging.NewMockTracer(ctrl)
	t2, tr2 := mocklogging.NewMockTracer(ctrl)
	tracer := NewMultiplexedTracer(t1, t2, &Tracer{})

	tr1.EXPECT().Debug("foo", "bar")
	tr2.EXPECT().Debug("foo", "bar")
	tracer.Debug("foo", "bar")
}

func TestTracerClose(t *testing.T) {
	ctrl := gomock.NewController(t)

	t1, tr1 := mocklogging.NewMockTracer(ctrl)
	t2, tr2 := mocklogging.NewMockTracer(ctrl)
	tracer := NewMultiplexedTracer(t1, t2, &Tracer{})

	tr1.EXPECT().Close()
	tr2.EXPECT().Close()
	tracer.Close()
}
