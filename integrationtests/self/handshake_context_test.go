package self_test

import (
	"context"
	"errors"
	"github.com/Noooste/utls"
	"net"
	"testing"
	"time"

	"github.com/Noooste/uquic-go"
	"github.com/Noooste/uquic-go/logging"

	"github.com/stretchr/testify/require"
)

func TestHandshakeContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(20*time.Millisecond))
	defer cancel()

	conn := newUDPConnLocalhost(t)

	errChan := make(chan error, 1)
	go func() {
		_, err := quic.Dial(ctx, newUDPConnLocalhost(t), conn.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
		errChan <- err
	}()

	require.ErrorIs(t, <-errChan, context.DeadlineExceeded)
}

func TestHandshakeCancellationError(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	errChan := make(chan error, 1)
	conn := newUDPConnLocalhost(t)
	go func() {
		_, err := quic.Dial(ctx, newUDPConnLocalhost(t), conn.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
		errChan <- err
	}()

	cancel(errors.New("application cancelled"))
	require.EqualError(t, <-errChan, "application cancelled")
}

func TestConnContextOnServerSide(t *testing.T) {
	tlsGetConfigForClientContextChan := make(chan context.Context, 1)
	tlsGetCertificateContextChan := make(chan context.Context, 1)
	tracerContextChan := make(chan context.Context, 1)
	connContextChan := make(chan context.Context, 1)
	streamContextChan := make(chan context.Context, 1)

	tr := &quic.Transport{
		Conn: newUDPConnLocalhost(t),
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			return context.WithValue(ctx, "foo", "bar"), nil
		},
	}
	defer tr.Close()

	server, err := tr.Listen(
		&tls.Config{
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				tlsGetConfigForClientContextChan <- info.Context()
				tlsConf := getTLSConfig()
				tlsConf.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					tlsGetCertificateContextChan <- info.Context()
					return &tlsConf.Certificates[0], nil
				}
				return tlsConf, nil
			},
		},
		getQuicConfig(&quic.Config{
			Tracer: func(ctx context.Context, _ logging.Perspective, _ quic.ConnectionID) *logging.ConnectionTracer {
				tracerContextChan <- ctx
				return nil
			},
		}),
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	connContextChan <- serverConn.Context()
	str, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	streamContextChan <- str.Context()
	str.Write([]byte{1, 2, 3})

	_, err = c.AcceptUniStream(ctx)
	require.NoError(t, err)
	c.CloseWithError(1337, "bye")

	checkContext := func(c <-chan context.Context, checkCancellationCause bool) {
		t.Helper()
		var ctx context.Context
		select {
		case ctx = <-c:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for context")
		}

		val := ctx.Value("foo")
		require.NotNil(t, val)
		v := val.(string)
		require.Equal(t, "bar", v)

		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for context to be done")
		}

		if !checkCancellationCause {
			return
		}
		ctxErr := context.Cause(ctx)
		var appErr *quic.ApplicationError
		require.ErrorAs(t, ctxErr, &appErr)
		require.Equal(t, quic.ApplicationErrorCode(1337), appErr.ErrorCode)
	}

	checkContext(connContextChan, true)
	checkContext(tracerContextChan, true)
	checkContext(streamContextChan, true)
	// github.com/Noooste/utls cancels the context when the TLS handshake completes.
	checkContext(tlsGetConfigForClientContextChan, false)
	checkContext(tlsGetCertificateContextChan, false)
}

func TestConnContextRejection(t *testing.T) {
	t.Run("rejecting", func(t *testing.T) {
		testConnContextRejection(t, true)
	})
	t.Run("not rejecting", func(t *testing.T) {
		testConnContextRejection(t, false)
	})
}

func testConnContextRejection(t *testing.T, reject bool) {
	tr := &quic.Transport{
		Conn: newUDPConnLocalhost(t),
		ConnContext: func(ctx context.Context, ci *quic.ClientInfo) (context.Context, error) {
			if reject {
				return nil, errors.New("rejecting connection")
			}
			return context.WithValue(ctx, "addr", ci.RemoteAddr), nil
		},
	}
	defer tr.Close()

	server, err := tr.Listen(
		getTLSConfig(),
		getQuicConfig(nil),
	)
	require.NoError(t, err)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pc := newUDPConnLocalhost(t)
	c, err := quic.Dial(ctx, pc, server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	if reject {
		require.ErrorIs(t, err, &quic.TransportError{Remote: true, ErrorCode: quic.ConnectionRefused})
		return
	}
	require.NoError(t, err)
	defer c.CloseWithError(0, "")

	conn, err := server.Accept(ctx)
	require.NoError(t, err)
	require.Equal(t, pc.LocalAddr().String(), conn.Context().Value("addr").(net.Addr).String())
	conn.CloseWithError(0, "")
}

// Users are not supposed to return a fresh context from ConnContext, but we should handle it gracefully.
func TestConnContextFreshContext(t *testing.T) {
	tr := &quic.Transport{
		Conn: newUDPConnLocalhost(t),
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			return context.Background(), nil
		},
	}
	defer tr.Close()
	server, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	errChan := make(chan error, 1)
	go func() {
		conn, err := server.Accept(context.Background())
		if err != nil {
			errChan <- err
			return
		}
		conn.CloseWithError(1337, "bye")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := quic.Dial(ctx, newUDPConnLocalhost(t), server.Addr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	select {
	case <-c.Context().Done():
	case err := <-errChan:
		t.Fatalf("accept failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestContextOnClientSide(t *testing.T) {
	tlsServerConf := getTLSConfig()
	tlsServerConf.ClientAuth = tls.RequestClientCert
	server, err := quic.Listen(newUDPConnLocalhost(t), tlsServerConf, getQuicConfig(nil))
	require.NoError(t, err)
	defer server.Close()

	tlsContextChan := make(chan context.Context, 1)
	tracerContextChan := make(chan context.Context, 1)
	tlsConf := getTLSClientConfig()
	tlsConf.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		tlsContextChan <- info.Context()
		return &tlsServerConf.Certificates[0], nil
	}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), "foo", "bar")) //nolint:staticcheck
	conn, err := quic.Dial(
		ctx,
		newUDPConnLocalhost(t),
		server.Addr(),
		tlsConf,
		getQuicConfig(&quic.Config{
			Tracer: func(ctx context.Context, _ logging.Perspective, _ quic.ConnectionID) *logging.ConnectionTracer {
				tracerContextChan <- ctx
				return nil
			},
		}),
	)
	require.NoError(t, err)
	cancel()

	// Make sure the connection context is not cancelled (even though derived from the ctx passed to Dial)
	select {
	case <-conn.Context().Done():
		t.Fatal("context should not be cancelled")
	default:
	}

	checkContext := func(ctx context.Context, checkCancellationCause bool) {
		t.Helper()
		val := ctx.Value("foo")
		require.NotNil(t, val)
		require.Equal(t, "bar", val.(string))
		if !checkCancellationCause {
			return
		}
		ctxErr := context.Cause(ctx)
		var appErr *quic.ApplicationError
		require.ErrorAs(t, ctxErr, &appErr)
		require.EqualValues(t, 1337, appErr.ErrorCode)
	}

	checkContextFromChan := func(c <-chan context.Context, checkCancellationCause bool) {
		t.Helper()
		var ctx context.Context
		select {
		case ctx = <-c:
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for context")
		}
		checkContext(ctx, checkCancellationCause)
	}

	str, err := conn.OpenUniStream()
	require.NoError(t, err)
	conn.CloseWithError(1337, "bye")

	checkContext(conn.Context(), true)
	checkContext(str.Context(), true)
	// github.com/Noooste/utls cancels the context when the TLS handshake completes
	checkContextFromChan(tlsContextChan, false)
	checkContextFromChan(tracerContextChan, false)
}
