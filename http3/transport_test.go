package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type mockBody struct {
	reader   bytes.Reader
	readErr  error
	closeErr error
	closed   bool
}

// make sure the mockBody can be used as a http.Request.Body
var _ io.ReadCloser = &mockBody{}

func (m *mockBody) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	return m.reader.Read(p)
}

func (m *mockBody) SetData(data []byte) {
	m.reader = *bytes.NewReader(data)
}

func (m *mockBody) Close() error {
	m.closed = true
	return m.closeErr
}

func TestRequestValidation(t *testing.T) {
	var tr Transport

	for _, tt := range []struct {
		name                string
		req                 *http.Request
		expectedErr         string
		expectedErrContains string
	}{
		{
			name:        "plain HTTP",
			req:         mustNewRequest(http.MethodGet, "http://www.example.org/", nil),
			expectedErr: "http3: unsupported protocol scheme: http",
		},
		{
			name: "missing URL",
			req: func() *http.Request {
				r := mustNewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.URL = nil
				return r
			}(),
			expectedErr: "http3: nil Request.URL",
		},
		{
			name: "missing URL Host",
			req: func() *http.Request {
				r := mustNewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.URL.Host = ""
				return r
			}(),
			expectedErr: "http3: no Host in request URL",
		},
		{
			name: "missing header",
			req: func() *http.Request {
				r := mustNewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Header = nil
				return r
			}(),
			expectedErr: "http3: nil Request.Header",
		},
		{
			name: "invalid header name",
			req: func() *http.Request {
				r := mustNewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Header.Add("foobär", "value")
				return r
			}(),
			expectedErr: "http3: invalid http header field name \"foobär\"",
		},
		{
			name: "invalid header value",
			req: func() *http.Request {
				r := mustNewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Header.Add("foo", string([]byte{0x7}))
				return r
			}(),
			expectedErrContains: "http3: invalid http header field value",
		},
		{
			name: "invalid method",
			req: func() *http.Request {
				r := mustNewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Method = "foobär"
				return r
			}(),
			expectedErr: "http3: invalid method \"foobär\"",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.req.Body = &mockBody{}
			_, err := tr.RoundTrip(tt.req)
			if tt.expectedErr != "" {
				require.EqualError(t, err, tt.expectedErr)
			}
			if tt.expectedErrContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrContains)
			}
			require.True(t, tt.req.Body.(*mockBody).closed)
		})
	}
}

func TestTransportDialHostname(t *testing.T) {
	type hostnameConfig struct {
		dialHostname  string
		tlsServerName string
	}
	hostnameChan := make(chan hostnameConfig, 1)
	tr := &Transport{
		Dial: func(_ context.Context, hostname string, tlsConf *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			hostnameChan <- hostnameConfig{
				dialHostname:  hostname,
				tlsServerName: tlsConf.ServerName,
			}
			return nil, errors.New("test done")
		},
	}

	t.Run("port set", func(t *testing.T) {
		req := mustNewRequest(http.MethodGet, "https://quic-go.net:1234", nil)
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		require.EqualError(t, err, "test done")
		select {
		case c := <-hostnameChan:
			require.Equal(t, "quic-go.net:1234", c.dialHostname)
			require.Equal(t, "quic-go.net", c.tlsServerName)
		case <-time.After(1 * time.Second):
			t.Fatal("timeout")
		}
	})

	// if the request doesn't have a port, the default port is used
	t.Run("port not set", func(t *testing.T) {
		req := mustNewRequest(http.MethodGet, "https://quic-go.net", nil)
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		require.EqualError(t, err, "test done")
		select {
		case c := <-hostnameChan:
			require.Equal(t, "quic-go.net:443", c.dialHostname)
			require.Equal(t, "quic-go.net", c.tlsServerName)
		case <-time.After(1 * time.Second):
			t.Fatal("timeout")
		}
	})
}

func TestTransportDatagrams(t *testing.T) {
	// if the default quic.Config is used, the transport automatically enables QUIC datagrams
	t.Run("default quic.Config", func(t *testing.T) {
		testErr := errors.New("handshake error")
		tr := &Transport{
			EnableDatagrams: true,
			Dial: func(_ context.Context, _ string, _ *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				require.True(t, quicConf.EnableDatagrams)
				return nil, testErr
			},
		}
		req := mustNewRequest(http.MethodGet, "https://example.com", nil)
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		require.ErrorIs(t, err, testErr)
	})

	// if a custom quic.Config is used, the transport just checks that QUIC datagrams are enabled
	t.Run("custom quic.Config", func(t *testing.T) {
		tr := &Transport{
			EnableDatagrams: true,
			QUICConfig:      &quic.Config{EnableDatagrams: false},
			Dial: func(_ context.Context, _ string, _ *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				t.Fatal("dial should not be called")
				return nil, nil
			},
		}
		req := mustNewRequest(http.MethodGet, "https://example.com", nil)
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		require.EqualError(t, err, "HTTP Datagrams enabled, but QUIC Datagrams disabled")
	})
}

func TestTransportMultipleQUICVersions(t *testing.T) {
	qconf := &quic.Config{
		Versions: []quic.Version{protocol.Version2, protocol.Version1},
	}
	tr := &Transport{QUICConfig: qconf}
	req := mustNewRequest(http.MethodGet, "https://example.com", nil)
	_, err := tr.RoundTrip(req)
	require.EqualError(t, err, "can only use a single QUIC version for dialing a HTTP/3 connection")
}

func TestTransportConnectionReuse(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cl := NewMockSingleRoundTripper(mockCtrl)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	handshakeChan := make(chan struct{})
	close(handshakeChan)
	conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
	var dialCount int
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
			dialCount++
			return conn, nil
		},
		newClient: func(quic.EarlyConnection) singleRoundTripper { return cl },
	}

	req1 := mustNewRequest("GET", "https://quic-go.net/file1.html", nil)
	// if OnlyCachedConn is set, no connection is dialed
	_, err := tr.RoundTripOpt(req1, RoundTripOpt{OnlyCachedConn: true})
	require.ErrorIs(t, err, ErrNoCachedConn)
	require.Zero(t, dialCount)

	// the first request establishes the connection...
	cl.EXPECT().RoundTrip(req1).Return(&http.Response{Request: req1}, nil)
	rsp, err := tr.RoundTrip(req1)
	require.NoError(t, err)
	require.Equal(t, req1, rsp.Request)
	require.Equal(t, 1, dialCount)

	// ... which is then used for the second request
	req2 := mustNewRequest("GET", "https://quic-go.net/file2.html", nil)
	cl.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
	rsp, err = tr.RoundTrip(req2)
	require.NoError(t, err)
	require.Equal(t, req2, rsp.Request)
	require.Equal(t, 1, dialCount)
}

func TestTransportConnectionRedial(t *testing.T) {
	t.Run("timeout error", func(t *testing.T) {
		testTransportConnectionRedial(t, &qerr.IdleTimeoutError{}, nil)
	})

	t.Run("other error", func(t *testing.T) {
		testErr := errors.New("test error")
		testTransportConnectionRedial(t, testErr, testErr)
	})
}

func testTransportConnectionRedial(t *testing.T, dialErr, expectedErr error) {
	mockCtrl := gomock.NewController(t)
	cl := NewMockSingleRoundTripper(mockCtrl)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	handshakeChan := make(chan struct{})
	close(handshakeChan)
	conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
	var dialCount int
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
			dialCount++
			return conn, nil
		},
		newClient: func(quic.EarlyConnection) singleRoundTripper { return cl },
	}

	req1 := mustNewRequest("GET", "https://quic-go.net/file1.html", nil)
	cl.EXPECT().RoundTrip(req1).Return(&http.Response{Request: req1}, nil)
	rsp, err := tr.RoundTrip(req1)
	require.NoError(t, err)
	require.Equal(t, req1, rsp.Request)
	require.Equal(t, 1, dialCount)

	req2 := mustNewRequest("GET", "https://quic-go.net/file2.html", nil)
	cl.EXPECT().RoundTrip(req2).Return(nil, dialErr)
	if expectedErr == nil {
		cl.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
	}
	rsp, err = tr.RoundTrip(req2)
	if expectedErr == nil {
		require.NoError(t, err)
		require.Equal(t, req2, rsp.Request)
		require.Equal(t, 2, dialCount)
	} else {
		require.ErrorIs(t, err, expectedErr)
		require.Equal(t, 1, dialCount)
	}
}

func TestTransportConnetionRedialHandshakeError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cl := NewMockSingleRoundTripper(mockCtrl)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	handshakeChan := make(chan struct{})
	close(handshakeChan)
	conn.EXPECT().HandshakeComplete().Return(handshakeChan).MaxTimes(2)
	var dialCount int
	testErr := errors.New("handshake error")
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
			dialCount++
			if dialCount == 1 {
				return nil, testErr
			}
			return conn, nil
		},
		newClient: func(quic.EarlyConnection) singleRoundTripper { return cl },
	}

	req1 := mustNewRequest("GET", "https://quic-go.net/file1.html", nil)
	_, err := tr.RoundTrip(req1)
	require.ErrorIs(t, err, testErr)
	require.Equal(t, 1, dialCount)

	req2 := mustNewRequest("GET", "https://quic-go.net/file2.html", nil)
	cl.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
	rsp, err := tr.RoundTrip(req2)
	require.NoError(t, err)
	require.Equal(t, req2, rsp.Request)
	require.Equal(t, 2, dialCount)
}

func TestTransportCloseEstablishedConnections(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (quic.EarlyConnection, error) {
			return conn, nil
		},
		newClient: func(quic.EarlyConnection) singleRoundTripper {
			cl := NewMockSingleRoundTripper(mockCtrl)
			cl.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{}, nil)
			return cl
		},
	}
	req := mustNewRequest(http.MethodGet, "https://quic-go.net/foobar.html", nil)
	_, err := tr.RoundTrip(req)
	require.NoError(t, err)
	conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(0), "")
	require.NoError(t, tr.Close())
}

func TestTransportCloseInFlightDials(t *testing.T) {
	tr := &Transport{
		Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			var err error
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-time.After(time.Second):
				err = errors.New("timeout")
			}
			return nil, err
		},
	}
	req := mustNewRequest(http.MethodGet, "https://quic-go.net/foobar.html", nil)

	errChan := make(chan error, 1)
	go func() {
		_, err := tr.RoundTrip(req)
		errChan <- err
	}()

	select {
	case err := <-errChan:
		t.Fatalf("received unexpected error: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	require.NoError(t, tr.Close())
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportCloseIdleConnections(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn1 := mockquic.NewMockEarlyConnection(mockCtrl)
	conn2 := mockquic.NewMockEarlyConnection(mockCtrl)
	tr := &Transport{
		Dial: func(_ context.Context, hostname string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			switch hostname {
			case "site1.com:443":
				return conn1, nil
			case "site2.com:443":
				return conn2, nil
			default:
				t.Fatal("unexpected hostname")
				return nil, errors.New("unexpected hostname")
			}
		},
	}
	req1 := mustNewRequest(http.MethodGet, "https://site1.com", nil)
	req2 := mustNewRequest(http.MethodGet, "https://site2.com", nil)
	require.NotEqual(t, req1.Host, req2.Host)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	req1 = req1.WithContext(ctx1)
	req2 = req2.WithContext(ctx2)
	roundTripCalled := make(chan struct{})
	reqFinished := make(chan struct{})
	tr.newClient = func(quic.EarlyConnection) singleRoundTripper {
		cl := NewMockSingleRoundTripper(mockCtrl)
		cl.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(r *http.Request) (*http.Response, error) {
			roundTripCalled <- struct{}{}
			<-r.Context().Done()
			return nil, nil
		})
		return cl
	}
	go func() {
		tr.RoundTrip(req1)
		reqFinished <- struct{}{}
	}()
	go func() {
		tr.RoundTrip(req2)
		reqFinished <- struct{}{}
	}()
	<-roundTripCalled
	<-roundTripCalled
	// Both two requests are started.
	cancel1()
	<-reqFinished
	// req1 is finished
	conn1.EXPECT().CloseWithError(gomock.Any(), gomock.Any())
	tr.CloseIdleConnections()
	cancel2()
	<-reqFinished
	// all requests are finished
	conn2.EXPECT().CloseWithError(gomock.Any(), gomock.Any())
	tr.CloseIdleConnections()
}
