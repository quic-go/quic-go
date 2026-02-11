package self_test

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTrace struct {
	openRecorders atomic.Int32

	SchemasChecked []string
}

var _ qlogwriter.Trace = &mockTrace{}

func newMockTrace() *mockTrace {
	return &mockTrace{}
}

func (t *mockTrace) AddProducer() qlogwriter.Recorder {
	t.openRecorders.Add(1)
	return &mockRecorder{onClose: func() { t.openRecorders.Add(-1) }}
}

func (t *mockTrace) SupportsSchemas(schema string) bool {
	t.SchemasChecked = append(t.SchemasChecked, schema)
	return true
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
	assert.Empty(t, clientTrace.SchemasChecked)
	assert.Empty(t, serverTrace.SchemasChecked)
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
