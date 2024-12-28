package quic

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockIndexableConn struct{ addr net.Addr }

var _ indexableConn = &mockIndexableConn{}

func (m *mockIndexableConn) LocalAddr() net.Addr { return m.addr }

func TestMultiplexerAddNewPacketConns(t *testing.T) {
	conn1 := &mockIndexableConn{addr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1234}}
	getMultiplexer().AddConn(conn1)
	conn2 := &mockIndexableConn{addr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1235}}
	getMultiplexer().AddConn(conn2)

	require.NoError(t, getMultiplexer().RemoveConn(conn1))
	require.NoError(t, getMultiplexer().RemoveConn(conn2))
}

func TestMultiplexerPanicsOnDuplicateConn(t *testing.T) {
	conn := &mockIndexableConn{addr: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}}
	getMultiplexer().AddConn(conn)
	require.Panics(t, func() { getMultiplexer().AddConn(conn) })

	require.NoError(t, getMultiplexer().RemoveConn(conn))
	require.ErrorContains(t, getMultiplexer().RemoveConn(conn), "cannote remove connection")
}
