package self_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"

	"github.com/stretchr/testify/assert"
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
		t.Logf("issuing %d byte connection ID from the server", serverConnIDLen)
	}
	if clientConnIDGenerator != nil {
		t.Logf("using %d byte connection ID generator for the client", clientConnIDGenerator.ConnectionIDLen())
	} else {
		t.Logf("issuing %d byte connection ID from the client", clientConnIDLen)
	}

	// setup server
	serverTr := &quic.Transport{
		Conn:                  newUDPConnLocalhost(t),
		ConnectionIDLength:    serverConnIDLen,
		ConnectionIDGenerator: serverConnIDGenerator,
	}
	defer serverTr.Close()
	addTracer(serverTr)
	serverCounter, serverTracer := newPacketTracer()
	ln, err := serverTr.Listen(
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
				return serverTracer
			},
		}),
	)
	require.NoError(t, err)

	// setup client
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var conn quic.Connection
	clientCounter, clientTracer := newPacketTracer()
	clientQUICConf := getQuicConfig(&quic.Config{
		Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
			return clientTracer
		},
	})
	if clientConnIDGenerator == nil && clientConnIDLen == 0 {
		conn, err = quic.Dial(ctx, newUDPConnLocalhost(t), ln.Addr(), getTLSClientConfig(), clientQUICConf)
		require.NoError(t, err)
	} else {
		clientTr := &quic.Transport{
			Conn:                  newUDPConnLocalhost(t),
			ConnectionIDLength:    clientConnIDLen,
			ConnectionIDGenerator: clientConnIDGenerator,
		}
		defer clientTr.Close()
		addTracer(clientTr)
		conn, err = clientTr.Dial(ctx, ln.Addr(), getTLSClientConfig(), clientQUICConf)
		require.NoError(t, err)
	}

	serverConn, err := ln.Accept(context.Background())
	require.NoError(t, err)
	serverStr, err := serverConn.OpenStream()
	require.NoError(t, err)

	go func() {
		serverStr.Write(PRData)
		serverStr.Close()
	}()

	str, err := conn.AcceptStream(context.Background())
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)

	conn.CloseWithError(0, "")
	serverConn.CloseWithError(0, "")

	for _, p := range serverCounter.getRcvdShortHeaderPackets() {
		expectedLen := serverConnIDLen
		if serverConnIDGenerator != nil {
			expectedLen = serverConnIDGenerator.ConnectionIDLen()
		}
		if !assert.Equal(t, expectedLen, p.hdr.DestConnectionID.Len(), "server conn length mismatch") {
			break
		}
	}
	for _, p := range clientCounter.getRcvdShortHeaderPackets() {
		expectedLen := clientConnIDLen
		if clientConnIDGenerator != nil {
			expectedLen = clientConnIDGenerator.ConnectionIDLen()
		}
		if !assert.Equal(t, expectedLen, p.hdr.DestConnectionID.Len(), "client conn length mismatch") {
			break
		}
	}
}
