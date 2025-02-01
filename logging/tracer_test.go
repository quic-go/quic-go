package logging_test

import (
	"net"
	"testing"

	"github.com/Noooste/quic-go/internal/protocol"
	. "github.com/Noooste/quic-go/logging"

	"github.com/stretchr/testify/require"
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
	var s1, s2 ByteCount
	t1 := &Tracer{SentPacket: func(_ net.Addr, _ *Header, s ByteCount, _ []Frame) { s1 = s }}
	t2 := &Tracer{SentPacket: func(_ net.Addr, _ *Header, s ByteCount, _ []Frame) { s2 = s }}
	tracer := NewMultiplexedTracer(t1, t2, &Tracer{})

	const size ByteCount = 1024
	remote := &net.UDPAddr{IP: net.IPv4(4, 3, 2, 1)}
	hdr := &Header{DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}
	f := &MaxDataFrame{MaximumData: 1337}
	tracer.SentPacket(remote, hdr, size, []Frame{f})
	require.Equal(t, size, s1)
	require.Equal(t, size, s2)
}
