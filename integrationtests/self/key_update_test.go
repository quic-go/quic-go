package self_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyUpdates(t *testing.T) {
	reset := handshake.SetKeyUpdateInterval(1) // update keys as frequently as possible
	t.Cleanup(reset)

	countKeyPhases := func(events []qlogwriter.Event) (sent, received int) {
		lastKeyPhaseSend := protocol.KeyPhaseOne
		lastKeyPhaseReceive := protocol.KeyPhaseOne
		for _, ev := range events {
			switch ev := ev.(type) {
			case qlog.PacketSent:
				if ev.Header.KeyPhaseBit != lastKeyPhaseSend {
					sent++
					lastKeyPhaseSend = ev.Header.KeyPhaseBit
				}
			case qlog.PacketReceived:
				if ev.Header.KeyPhaseBit != lastKeyPhaseReceive {
					received++
					lastKeyPhaseReceive = ev.Header.KeyPhaseBit
				}
			}
		}
		return
	}

	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), nil)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var eventRecorder events.Recorder
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{Tracer: newTracer(&eventRecorder)}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	serverErrChan := make(chan error, 1)
	go func() {
		str, err := serverConn.OpenUniStream()
		if err != nil {
			serverErrChan <- err
			return
		}
		defer str.Close()
		if _, err := str.Write(PRDataLong); err != nil {
			serverErrChan <- err
			return
		}
		close(serverErrChan)
	}()

	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRDataLong, data)
	require.NoError(t, conn.CloseWithError(0, ""))

	require.NoError(t, <-serverErrChan)

	keyPhasesSent, keyPhasesReceived := countKeyPhases(eventRecorder.Events())
	t.Logf("Used %d key phases on outgoing and %d key phases on incoming packets.", keyPhasesSent, keyPhasesReceived)
	assert.Greater(t, keyPhasesReceived, 10)
	assert.InDelta(t, keyPhasesSent, keyPhasesReceived, 2)
}
