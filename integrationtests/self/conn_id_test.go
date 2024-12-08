package self_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

type connIDGenerator struct {
	Length int
}

var _ quic.ConnectionIDGenerator = &connIDGenerator{}

func (c *connIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, c.Length)
	if _, err := rand.Read(b); err != nil {
		return quic.ConnectionID{}, fmt.Errorf("generating conn ID failed: %w", err)
	}
	return protocol.ParseConnectionID(b), nil
}

func (c *connIDGenerator) ConnectionIDLen() int { return c.Length }

func randomConnIDLen() int { return 2 + int(mrand.Int31n(19)) }

func TestConnectionIDsZeroLength(t *testing.T) {
	testTransferWithConnectionIDs(t, randomConnIDLen(), 0, nil, nil)
}

func TestConnectionIDsRandomLengths(t *testing.T) {
	testTransferWithConnectionIDs(t, randomConnIDLen(), randomConnIDLen(), nil, nil)
}

func TestConnectionIDsCustomGenerator(t *testing.T) {
	testTransferWithConnectionIDs(t, 0, 0,
		&connIDGenerator{Length: randomConnIDLen()},
		&connIDGenerator{Length: randomConnIDLen()},
	)
}

// connIDLen is ignored when connIDGenerator is set
func testTransferWithConnectionIDs(
	t *testing.T,
	serverConnIDLen, clientConnIDLen int,
	serverConnIDGenerator, clientConnIDGenerator quic.ConnectionIDGenerator,
) {
	t.Helper()

	if serverConnIDGenerator != nil {
		t.Logf("using %d byte connection ID generator for the server", serverConnIDGenerator.ConnectionIDLen())
	} else {
		t.Logf("using %d byte connection ID for the server", serverConnIDLen)
	}
	if clientConnIDGenerator != nil {
		t.Logf("using %d byte connection ID generator for the client", clientConnIDGenerator.ConnectionIDLen())
	} else {
		t.Logf("using %d byte connection ID for the client", clientConnIDLen)
	}

	// setup server
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	serverTr := &quic.Transport{
		Conn:                  conn,
		ConnectionIDLength:    serverConnIDLen,
		ConnectionIDGenerator: serverConnIDGenerator,
	}
	t.Cleanup(func() { serverTr.Close() })
	addTracer(serverTr)
	ln, err := serverTr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	// setup client
	laddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	clientConn, err := net.ListenUDP("udp", laddr)
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.Close() })
	clientTr := &quic.Transport{
		Conn:                  clientConn,
		ConnectionIDLength:    clientConnIDLen,
		ConnectionIDGenerator: clientConnIDGenerator,
	}
	t.Cleanup(func() { clientTr.Close() })
	addTracer(clientTr)

	cl, err := clientTr.Dial(
		context.Background(),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ln.Addr().(*net.UDPAddr).Port},
		getTLSClientConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	t.Cleanup(func() { cl.CloseWithError(0, "") })

	serverConn, err := ln.Accept(context.Background())
	require.NoError(t, err)
	serverStr, err := serverConn.OpenStream()
	require.NoError(t, err)
	t.Cleanup(func() { serverConn.CloseWithError(0, "") })

	go func() {
		serverStr.Write(PRData)
		serverStr.Close()
	}()

	str, err := cl.AcceptStream(context.Background())
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)
}
