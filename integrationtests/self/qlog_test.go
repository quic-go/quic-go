package self_test

import (
	"bytes"
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTrace struct {
	openRecorders atomic.Int32
}

var _ qlogwriter.Trace = &mockTrace{}

func newMockTrace() *mockTrace {
	return &mockTrace{}
}

func (t *mockTrace) AddProducer() qlogwriter.Recorder {
	t.openRecorders.Add(1)
	return &mockRecorder{onClose: func() { t.openRecorders.Add(-1) }}
}

func (t *mockTrace) OpenRecorders() int {
	return int(t.openRecorders.Load())
}

type mockRecorder struct {
	onClose func()
}

var _ qlogwriter.Recorder = &mockRecorder{}

func (r *mockRecorder) RecordEvent(qlogwriter.Event) {}

func (r *mockRecorder) Close() error {
	r.onClose()
	return nil
}

func TestQlogHandshake(t *testing.T) {
	serverTrace := newMockTrace()
	clientTrace := newMockTrace()

	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return serverTrace
			},
		}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
				return clientTrace
			},
		}),
	)
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	assert.NotZero(t, clientTrace.OpenRecorders())
	assert.NotZero(t, serverTrace.OpenRecorders())

	clientConn.CloseWithError(0, "")
	serverConn.CloseWithError(0, "")

	assert.Zero(t, clientTrace.OpenRecorders(), "client recorders should be closed")
	assert.Zero(t, serverTrace.OpenRecorders(), "server recorders should be closed")
}

func TestQlogIPRedaction(t *testing.T) {
	var serverEvents, clientEvents events.Recorder
	redact := func(addr netip.AddrPort, isLocal bool) (string, bool) {
		if isLocal {
			return "", true
		}
		return "***", true
	}
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{Tracer: qlog.RedactIPs(newTracer(&serverEvents), redact)}),
	)
	require.NoError(t, err)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clientConn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{Tracer: qlog.RedactIPs(newTracer(&clientEvents), redact)}),
	)
	require.NoError(t, err)
	defer clientConn.CloseWithError(0, "")
	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	for _, recorder := range []*events.Recorder{&serverEvents, &clientEvents} {
		connections := recorder.Events(qlog.StartedConnection{})
		require.Len(t, connections, 1)
		conn := connections[0].(qlog.StartedConnection)
		require.Equal(t, new(""), conn.RedactedLocal)
		require.Equal(t, new("***"), conn.RedactedRemote)
		require.Equal(t, "127.0.0.1", conn.Local.IPv4.Addr().String())
		require.Equal(t, "127.0.0.1", conn.Remote.IPv4.Addr().String())
		var buf bytes.Buffer
		require.NoError(t, conn.Encode(jsontext.NewEncoder(&buf), time.Time{}))
		require.JSONEq(t, `{
			"local": {"address_v4": ""},
			"remote": {"address_v4": "***"}
		}`, buf.String())
	}
}

func TestQlogHandshakeFailed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const handshakeIdleTimeout = 3 * time.Second

		clientTrace := newMockTrace()
		clientPacketConn, serverPacketConn, closeFn := newSimnetLink(t, time.Millisecond)
		defer closeFn(t)

		// Don't start a server, so the handshake will timeout
		errChan := make(chan error, 1)
		go func() {
			_, err := quic.Dial(
				context.Background(),
				clientPacketConn,
				serverPacketConn.LocalAddr(),
				getTLSClientConfig(),
				getQuicConfig(&quic.Config{
					HandshakeIdleTimeout: handshakeIdleTimeout,
					Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
						return clientTrace
					},
				}),
			)
			errChan <- err
		}()

		select {
		case err := <-errChan:
			require.ErrorIs(t, err, &quic.IdleTimeoutError{})
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for dial error")
		}

		require.Zero(t, clientTrace.OpenRecorders(), "client recorders should be closed after failed handshake")
	})
}
