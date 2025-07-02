package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/assert"
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
			req:         httptest.NewRequest(http.MethodGet, "http://www.example.org/", nil),
			expectedErr: "http3: unsupported protocol scheme: http",
		},
		{
			name: "missing URL",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.URL = nil
				return r
			}(),
			expectedErr: "http3: nil Request.URL",
		},
		{
			name: "missing URL Host",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.URL.Host = ""
				return r
			}(),
			expectedErr: "http3: no Host in request URL",
		},
		{
			name: "missing header",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Header = nil
				return r
			}(),
			expectedErr: "http3: nil Request.Header",
		},
		{
			name: "invalid header name",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Header.Add("foobär", "value")
				return r
			}(),
			expectedErr: "http3: invalid http header field name \"foobär\"",
		},
		{
			name: "invalid header value",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://www.example.org/", nil)
				r.Header.Add("foo", string([]byte{0x7}))
				return r
			}(),
			expectedErrContains: "http3: invalid http header field value",
		},
		{
			name: "invalid method",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "https://www.example.org/", nil)
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
		Dial: func(_ context.Context, hostname string, tlsConf *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			hostnameChan <- hostnameConfig{
				dialHostname:  hostname,
				tlsServerName: tlsConf.ServerName,
			}
			return nil, errors.New("test done")
		},
	}

	t.Run("port set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://quic-go.net:1234", nil)
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
		req := httptest.NewRequest(http.MethodGet, "https://quic-go.net", nil)
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
		tr := &Transport{
			EnableDatagrams: true,
			Dial: func(_ context.Context, _ string, _ *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
				require.True(t, quicConf.EnableDatagrams)
				return nil, assert.AnError
			},
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		require.ErrorIs(t, err, assert.AnError)
	})

	// if a custom quic.Config is used, the transport just checks that QUIC datagrams are enabled
	t.Run("custom quic.Config", func(t *testing.T) {
		tr := &Transport{
			EnableDatagrams: true,
			QUICConfig:      &quic.Config{EnableDatagrams: false},
			Dial: func(_ context.Context, _ string, _ *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
				t.Fatal("dial should not be called")
				return nil, nil
			},
		}
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		_, err := tr.RoundTripOpt(req, RoundTripOpt{})
		require.EqualError(t, err, "HTTP Datagrams enabled, but QUIC Datagrams disabled")
	})
}

func TestTransportMultipleQUICVersions(t *testing.T) {
	qconf := &quic.Config{
		Versions: []quic.Version{quic.Version2, quic.Version1},
	}
	tr := &Transport{QUICConfig: qconf}
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	_, err := tr.RoundTrip(req)
	require.EqualError(t, err, "can only use a single QUIC version for dialing a HTTP/3 connection")
}

func TestTransportConnectionReuse(t *testing.T) {
	conn, _ := newConnPair(t)
	mockCtrl := gomock.NewController(t)
	cl := NewMockClientConn(mockCtrl)
	var dialCount int
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			dialCount++
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return cl },
	}

	req1 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file1.html", nil)
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
	req2 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file2.html", nil)
	cl.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
	rsp, err = tr.RoundTrip(req2)
	require.NoError(t, err)
	require.Equal(t, req2, rsp.Request)
	require.Equal(t, 1, dialCount)
}

// Requests reuse the same underlying QUIC connection.
// If a request experiences an error, the behavior depends on the nature of that error.
func TestTransportConnectionRedial(t *testing.T) {
	nonRetryableReq := httptest.NewRequest(
		http.MethodGet,
		"https://quic-go.org",
		strings.NewReader("foobar"),
	)
	require.Nil(t, nonRetryableReq.GetBody)

	retryableReq := nonRetryableReq.Clone(context.Background())
	retryableReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("foobaz")), nil
	}

	// If the error occurs when opening the stream, it is safe to retry the request:
	// We can be certain that it wasn't sent out (not even partially).
	t.Run("error when opening the stream", func(t *testing.T) {
		require.NoError(t,
			testTransportConnectionRedial(t, nonRetryableReq, &errConnUnusable{errors.New("test")}, "foobar", true),
		)
	})

	// If the error occurs when opening the stream, it is safe to retry the request:
	// We can be certain that it wasn't sent out (not even partially).
	t.Run("non-retryable request error after opening the stream", func(t *testing.T) {
		require.ErrorIs(t,
			testTransportConnectionRedial(t, nonRetryableReq, assert.AnError, "foobar", false),
			assert.AnError,
		)
	})

	t.Run("retryable request after opening the stream", func(t *testing.T) {
		require.ErrorIs(t,
			testTransportConnectionRedial(t, retryableReq, assert.AnError, "", false),
			assert.AnError,
		)
	})

	t.Run("retryable request after H3_REQUEST_REJECTED", func(t *testing.T) {
		require.NoError(t,
			testTransportConnectionRedial(t,
				retryableReq,
				&Error{ErrorCode: ErrCodeRequestRejected},
				"foobaz",
				true,
			),
		)
	})

	t.Run("retryable request where GetBody returns an error", func(t *testing.T) {
		req := nonRetryableReq.Clone(context.Background())
		req.GetBody = func() (io.ReadCloser, error) {
			return nil, assert.AnError
		}
		require.ErrorIs(t,
			testTransportConnectionRedial(t, req, &Error{ErrorCode: ErrCodeRequestRejected}, "", false),
			assert.AnError,
		)
	})
}

func testTransportConnectionRedial(t *testing.T, req *http.Request, roundtripErr error, expectedBody string, expectRedial bool) error {
	conn, _ := newConnPair(t)
	mockCtrl := gomock.NewController(t)
	cl := NewMockClientConn(mockCtrl)
	var dialCount int
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			dialCount++
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return cl },
	}

	var body string
	cl.EXPECT().RoundTrip(req).Return(nil, roundtripErr)
	if expectRedial {
		cl.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(r *http.Request) (*http.Response, error) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				panic(fmt.Sprintf("reading body failed: %v", err))
			}
			body = string(b)
			return &http.Response{Request: req}, nil
		})
	}

	_, err := tr.RoundTrip(req)
	if !expectRedial {
		assert.Equal(t, 1, dialCount)
	} else {
		assert.Equal(t, 2, dialCount)
		assert.Equal(t, expectedBody, body)
	}
	return err
}

func TestTransportRequestContextCancellation(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cl := NewMockClientConn(mockCtrl)
	conn, _ := newConnPair(t)
	var dialCount int
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			dialCount++
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return cl },
	}

	// the first request succeeds
	req1 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file1.html", nil)
	cl.EXPECT().RoundTrip(req1).Return(&http.Response{Request: req1}, nil)
	rsp, err := tr.RoundTrip(req1)
	require.NoError(t, err)
	require.Equal(t, req1, rsp.Request)
	require.Equal(t, 1, dialCount)

	// the second request reuses the QUIC connection, and runs into the cancelled context
	req2 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file2.html", nil)
	ctx, cancel := context.WithCancel(context.Background())
	req2 = req2.WithContext(ctx)
	cl.EXPECT().RoundTrip(req2).DoAndReturn(
		func(r *http.Request) (*http.Response, error) {
			cancel()
			return nil, context.Canceled
		},
	)
	_, err = tr.RoundTrip(req2)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, dialCount)

	// the next request reuses the QUIC connection
	req3 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file2.html", nil)
	cl.EXPECT().RoundTrip(req3).Return(&http.Response{Request: req3}, nil)
	rsp, err = tr.RoundTrip(req3)
	require.NoError(t, err)
	require.Equal(t, req3, rsp.Request)
	require.Equal(t, 1, dialCount)
}

func TestTransportConnetionRedialHandshakeError(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cl := NewMockClientConn(mockCtrl)
	conn, _ := newConnPair(t)
	var dialCount int
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			dialCount++
			if dialCount == 1 {
				return nil, assert.AnError
			}
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return cl },
	}

	req1 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file1.html", nil)
	_, err := tr.RoundTrip(req1)
	require.ErrorIs(t, err, assert.AnError)
	require.Equal(t, 1, dialCount)

	req2 := httptest.NewRequest(http.MethodGet, "https://quic-go.net/file2.html", nil)
	cl.EXPECT().RoundTrip(req2).Return(&http.Response{Request: req2}, nil)
	rsp, err := tr.RoundTrip(req2)
	require.NoError(t, err)
	require.Equal(t, req2, rsp.Request)
	require.Equal(t, 2, dialCount)
}

func TestTransportCloseEstablishedConnections(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn, _ := newConnPair(t)
	tr := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
		newClientConn: func(*quic.Conn) clientConn {
			cl := NewMockClientConn(mockCtrl)
			cl.EXPECT().RoundTrip(gomock.Any()).Return(&http.Response{}, nil)
			return cl
		},
	}
	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/foobar.html", nil)
	_, err := tr.RoundTrip(req)
	require.NoError(t, err)
	require.NoError(t, tr.Close())

	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestTransportCloseInFlightDials(t *testing.T) {
	tr := &Transport{
		Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
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
	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net/foobar.html", nil)

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
	conn1, _ := newConnPair(t)
	conn2, _ := newConnPair(t)
	roundTripCalled := make(chan struct{})
	tr := &Transport{
		Dial: func(_ context.Context, hostname string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
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
		newClientConn: func(*quic.Conn) clientConn {
			cl := NewMockClientConn(mockCtrl)
			cl.EXPECT().RoundTrip(gomock.Any()).DoAndReturn(func(r *http.Request) (*http.Response, error) {
				roundTripCalled <- struct{}{}
				<-r.Context().Done()
				return nil, nil
			})
			return cl
		},
	}
	req1 := httptest.NewRequest(http.MethodGet, "https://site1.com", nil)
	req2 := httptest.NewRequest(http.MethodGet, "https://site2.com", nil)
	require.NotEqual(t, req1.Host, req2.Host)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	req1 = req1.WithContext(ctx1)
	req2 = req2.WithContext(ctx2)
	reqFinished := make(chan struct{})
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
	tr.CloseIdleConnections()
	select {
	case <-conn1.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	cancel2()
	<-reqFinished
	// all requests are finished
	tr.CloseIdleConnections()
	select {
	case <-conn2.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
