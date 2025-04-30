package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConfigureTLSConfig(t *testing.T) {
	t.Run("basic config", func(t *testing.T) {
		conf := ConfigureTLSConfig(&tls.Config{})
		require.Equal(t, conf.NextProtos, []string{NextProtoH3})
	})

	t.Run("ALPN set", func(t *testing.T) {
		conf := ConfigureTLSConfig(&tls.Config{NextProtos: []string{"foo", "bar"}})
		require.Equal(t, []string{NextProtoH3}, conf.NextProtos)
	})

	// for configs that define GetConfigForClient, the ALPN is set to h3
	t.Run("GetConfigForClient", func(t *testing.T) {
		staticConf := &tls.Config{NextProtos: []string{"foo", "bar"}}
		conf := ConfigureTLSConfig(&tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return staticConf, nil
			},
		})
		innerConf, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
		require.NoError(t, err)
		require.NotNil(t, innerConf)
		require.Equal(t, []string{NextProtoH3}, innerConf.NextProtos)
		// make sure the original config was not modified
		require.Equal(t, []string{"foo", "bar"}, staticConf.NextProtos)
	})

	// GetConfigForClient might return a nil tls.Config
	t.Run("GetConfigForClient returns nil", func(t *testing.T) {
		conf := ConfigureTLSConfig(&tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return nil, nil
			},
		})
		innerConf, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
		require.NoError(t, err)
		require.Nil(t, innerConf)
	})
}

func TestServerSettings(t *testing.T) {
	t.Run("enable datagrams", func(t *testing.T) {
		testServerSettings(t, true, nil)
	})
	t.Run("additional settings", func(t *testing.T) {
		testServerSettings(t, false, map[uint64]uint64{13: 37})
	})
}

func testServerSettings(t *testing.T, enableDatagrams bool, other map[uint64]uint64) {
	s := Server{
		EnableDatagrams:    enableDatagrams,
		AdditionalSettings: other,
	}
	s.init()

	testDone := make(chan struct{})
	defer close(testDone)
	settingsChan := make(chan []byte)
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		settingsChan <- b
		return len(b), nil
	})

	conn.EXPECT().OpenUniStream().Return(controlStr, nil)
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-testDone
		return nil, assert.AnError
	}).MaxTimes(1)
	conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(ctx context.Context) (quic.Stream, error) {
		<-testDone
		return nil, assert.AnError
	}).MaxTimes(1)
	conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	conn.EXPECT().LocalAddr().AnyTimes()
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()

	go s.handleConn(conn)

	select {
	case b := <-settingsChan:
		typ, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		require.EqualValues(t, streamTypeControlStream, typ)
		fp := (&frameParser{r: bytes.NewReader(b[l:])})
		f, err := fp.ParseNext()
		require.NoError(t, err)
		require.IsType(t, &settingsFrame{}, f)
		settingsFrame := f.(*settingsFrame)
		// Extended CONNECT is always supported
		require.True(t, settingsFrame.ExtendedConnect)
		require.Equal(t, settingsFrame.Datagram, enableDatagrams)
		require.Equal(t, settingsFrame.Other, other)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func decodeHeader(t *testing.T, r io.Reader) map[string][]string {
	fields := make(map[string][]string)
	decoder := qpack.NewDecoder(nil)

	frame, err := (&frameParser{r: r}).ParseNext()
	require.NoError(t, err)
	require.IsType(t, &headersFrame{}, frame)
	headersFrame := frame.(*headersFrame)
	data := make([]byte, headersFrame.Length)
	_, err = io.ReadFull(r, data)
	require.NoError(t, err)
	hfs, err := decoder.DecodeFull(data)
	require.NoError(t, err)
	for _, p := range hfs {
		fields[p.Name] = append(fields[p.Name], p.Value)
	}
	return fields
}

func TestServerRequestHandling(t *testing.T) {
	t.Run("200 with an empty handler", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {},
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
		)
		require.Equal(t, hfs[":status"], []string{"200"})
		require.Empty(t, body)
	})

	t.Run("content-length", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
				w.Write([]byte("foobar"))
			},
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
		)
		require.Equal(t, hfs[":status"], []string{"418"})
		require.Equal(t, hfs["content-length"], []string{"6"})
		require.Equal(t, body, []byte("foobar"))
	})

	t.Run("no content-length when flushed", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foo"))
				w.(http.Flusher).Flush()
				w.Write([]byte("bar"))
			},
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
		)
		require.Equal(t, hfs[":status"], []string{"200"})
		require.NotContains(t, hfs, "content-length")
		require.Equal(t, body, []byte("foobar"))
	})

	t.Run("HEAD request", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("foobar"))
			},
			httptest.NewRequest(http.MethodHead, "https://www.example.com", nil),
		)
		require.Equal(t, hfs[":status"], []string{"200"})
		require.Empty(t, body)
	})

	t.Run("POST request", func(t *testing.T) {
		hfs, body := testServerRequestHandling(t,
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
				data, _ := io.ReadAll(r.Body)
				w.Write(data)
			},
			httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
		)
		require.Equal(t, hfs[":status"], []string{"418"})
		require.Equal(t, []byte("foobar"), body)
	})
}

func encodeRequest(t *testing.T, req *http.Request) io.Reader {
	var buf bytes.Buffer
	rw := newRequestWriter()
	require.NoError(t, rw.WriteRequestHeader(&buf, req, false))
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		buf.Write((&dataFrame{Length: uint64(len(body))}).Append(nil))
		buf.Write(body)
	}
	return bytes.NewReader(buf.Bytes())
}

func testServerRequestHandling(t *testing.T,
	handler http.HandlerFunc,
	req *http.Request,
) (responseHeaders map[string][]string, body []byte) {
	responseBuf := &bytes.Buffer{}
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
	str.EXPECT().CancelRead(gomock.Any())
	str.EXPECT().Close()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(encodeRequest(t, req).Read).AnyTimes()

	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		Handler:   handler,
	}

	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	qconn.EXPECT().LocalAddr().AnyTimes()
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
	qconn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn := newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)

	s.handleRequest(conn, str, nil, qpack.NewDecoder(nil))
	hfs := decodeHeader(t, responseBuf)
	fp := frameParser{r: responseBuf}
	var content []byte
	for {
		frame, err := fp.ParseNext()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		require.IsType(t, &dataFrame{}, frame)
		b := make([]byte, frame.(*dataFrame).Length)
		_, err = io.ReadFull(responseBuf, b)
		require.NoError(t, err)
		content = append(content, b...)
	}
	return hfs, content
}

func TestServerHandlerBodyNotRead(t *testing.T) {
	t.Run("GET request with a body", func(t *testing.T) {
		testServerHandlerBodyNotRead(t,
			httptest.NewRequest(http.MethodGet, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			func(w http.ResponseWriter, r *http.Request) {},
		)
	})

	t.Run("POST body not read", func(t *testing.T) {
		testServerHandlerBodyNotRead(t,
			httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			func(w http.ResponseWriter, r *http.Request) {},
		)
	})

	t.Run("POST request, with a replaced body", func(t *testing.T) {
		testServerHandlerBodyNotRead(t,
			httptest.NewRequest(http.MethodPost, "https://www.example.com", bytes.NewBuffer([]byte("foobar"))),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = struct {
					io.Reader
					io.Closer
				}{}
			},
		)
	})
}

func TestServerFirstFrameNotHeaders(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Write(gomock.Any()).AnyTimes()
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	var buf bytes.Buffer
	buf.Write((&dataFrame{Length: 6}).Append(nil))
	buf.Write([]byte("foobar"))
	str.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

	s := &Server{TLSConfig: testdata.GetTLSConfig()}

	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	qconn.EXPECT().LocalAddr().AnyTimes()
	qconn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any())
	conn := newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)

	s.handleRequest(conn, str, nil, qpack.NewDecoder(nil))
}

func testServerHandlerBodyNotRead(t *testing.T, req *http.Request, handler http.HandlerFunc) {
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Write(gomock.Any()).AnyTimes()
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeNoError))
	str.EXPECT().Close().MaxTimes(1)
	str.EXPECT().Read(gomock.Any()).DoAndReturn(encodeRequest(t, req).Read).AnyTimes()

	var called bool
	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			handler(w, r)
		}),
	}

	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	qconn.EXPECT().LocalAddr().AnyTimes()
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
	qconn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn := newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)

	s.handleRequest(conn, str, nil, qpack.NewDecoder(nil))
	require.True(t, called)
}

func TestServerStreamResetByClient(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	done := make(chan struct{})
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete)).Do(func(quic.StreamErrorCode) { close(done) })
	str.EXPECT().Read(gomock.Any()).Return(0, assert.AnError)

	var called bool
	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}),
	}

	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	qconn.EXPECT().LocalAddr().AnyTimes()
	conn := newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)

	s.handleRequest(conn, str, nil, qpack.NewDecoder(nil))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.False(t, called)
}

func TestServerPanickingHandler(t *testing.T) {
	t.Run("panicking handler", func(t *testing.T) {
		logOutput := testServerPanickingHandler(t, func(w http.ResponseWriter, r *http.Request) {
			panic("foobar")
		})
		require.Contains(t, logOutput, "http3: panic serving")
		require.Contains(t, logOutput, "foobar")
	})

	t.Run("http.ErrAbortHandler", func(t *testing.T) {
		logOutput := testServerPanickingHandler(t, func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		})
		require.NotContains(t, logOutput, "http3: panic serving")
		require.NotContains(t, logOutput, "http.ErrAbortHandler")
	})
}

func testServerPanickingHandler(t *testing.T, handler http.HandlerFunc) (logOutput string) {
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeInternalError))
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeInternalError))
	str.EXPECT().Read(gomock.Any()).DoAndReturn(
		encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)).Read,
	).AnyTimes()

	var logBuf bytes.Buffer
	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		Handler:   handler,
		Logger:    slog.New(slog.NewTextHandler(&logBuf, nil)),
	}

	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	qconn.EXPECT().LocalAddr().AnyTimes()
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
	qconn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn := newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)

	s.handleRequest(conn, str, nil, qpack.NewDecoder(nil))
	return logBuf.String()
}

func TestServerRequestHeaderTooLarge(t *testing.T) {
	t.Run("default value", func(t *testing.T) {
		// use 2*DefaultMaxHeaderBytes here. qpack will compress the request,
		// but the request will still end up larger than DefaultMaxHeaderBytes.
		url := bytes.Repeat([]byte{'a'}, http.DefaultMaxHeaderBytes*2)
		testServerRequestHeaderTooLarge(t,
			httptest.NewRequest(http.MethodGet, "https://"+string(url), nil),
			0,
		)
	})

	t.Run("custom value", func(t *testing.T) {
		testServerRequestHeaderTooLarge(t,
			httptest.NewRequest(http.MethodGet, "https://www.example.com", nil),
			20,
		)
	})
}

func testServerRequestHeaderTooLarge(t *testing.T, req *http.Request, maxHeaderBytes int) {
	var called bool
	s := &Server{
		TLSConfig:      testdata.GetTLSConfig(),
		MaxHeaderBytes: maxHeaderBytes,
		Handler:        http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
	}
	s.init()

	done := make(chan struct{}, 2)
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeFrameError)).Do(func(quic.StreamErrorCode) { done <- struct{}{} })
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeFrameError)).Do(func(quic.StreamErrorCode) { done <- struct{}{} })
	str.EXPECT().Read(gomock.Any()).DoAndReturn(encodeRequest(t, req).Read).AnyTimes()

	testDone := make(chan struct{})
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any())
	conn.EXPECT().OpenUniStream().Return(controlStr, nil)
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-testDone
		return nil, assert.AnError
	}).MaxTimes(1)
	conn.EXPECT().AcceptStream(gomock.Any()).Return(str, nil)
	conn.EXPECT().AcceptStream(gomock.Any()).Return(nil, assert.AnError)
	conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	conn.EXPECT().LocalAddr().AnyTimes()
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()

	s.handleConn(conn)
	for range 2 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timeout")
		}
	}
	require.False(t, called)
}

func TestServerRequestContext(t *testing.T) {
	responseBuf := &bytes.Buffer{}
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	strCtx, strCtxCancel := context.WithCancel(context.Background())
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Context().Return(strCtx).AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
	str.EXPECT().CancelRead(gomock.Any())
	str.EXPECT().Close()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(
		encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)).Read,
	).AnyTimes()

	ctxChan := make(chan context.Context, 1)
	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctxChan <- r.Context()
		}),
	}
	s.init()

	testDone := make(chan struct{})
	defer close(testDone)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).AnyTimes()
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1337}).AnyTimes()
	conn.EXPECT().LocalAddr().Return(&net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 42}).AnyTimes()
	conn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
	connCtx := context.WithValue(context.Background(), "connection context", "connection context value")
	conn.EXPECT().Context().Return(connCtx).AnyTimes()
	conn.EXPECT().OpenUniStream().Return(str, nil)
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-testDone
		return nil, assert.AnError
	}).MaxTimes(1)
	conn.EXPECT().AcceptStream(gomock.Any()).Return(str, nil)
	conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
		<-testDone
		return nil, assert.AnError
	}).MaxTimes(1)

	go s.handleConn(conn)
	var requestContext context.Context
	select {
	case requestContext = <-ctxChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Equal(t, "connection context value", requestContext.Value("connection context"))
	require.Equal(t, s, requestContext.Value(ServerContextKey))
	require.Equal(t, &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2), Port: 42}, requestContext.Value(http.LocalAddrContextKey))
	require.Equal(t, &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1337}, requestContext.Value(RemoteAddrContextKey))
	select {
	case <-requestContext.Done():
		t.Fatal("request context was canceled")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	strCtxCancel()
	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Equal(t, context.Canceled, requestContext.Err())
}

func TestServerHTTPStreamHijacking(t *testing.T) {
	responseBuf := &bytes.Buffer{}
	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(responseBuf.Write).AnyTimes()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(
		encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)).Read,
	).AnyTimes()

	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.(HTTPStreamer).HTTPStream()
			str.Write([]byte("foobar"))
		}),
	}

	qconn := mockquic.NewMockEarlyConnection(mockCtrl)
	qconn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	qconn.EXPECT().LocalAddr().AnyTimes()
	qconn.EXPECT().ConnectionState().Return(quic.ConnectionState{})
	qconn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn := newConnection(context.Background(), qconn, false, protocol.PerspectiveServer, nil, 0)

	s.handleRequest(conn, str, nil, qpack.NewDecoder(nil))
	hfs := decodeHeader(t, responseBuf)
	require.Equal(t, hfs[":status"], []string{"200"})
	require.Equal(t, []byte("foobar"), responseBuf.Bytes())
}

func TestServerStreamHijacking(t *testing.T) {
	for _, bidirectional := range []bool{true, false} {
		name := "bidirectional"
		if !bidirectional {
			name = "unidirectional"
		}
		t.Run(name, func(t *testing.T) {
			t.Run("hijack", func(t *testing.T) {
				testServerHijackBidirectionalStream(t, bidirectional, true, nil)
			})
			t.Run("don't hijack", func(t *testing.T) {
				testServerHijackBidirectionalStream(t, bidirectional, false, nil)
			})
			t.Run("hijacker error", func(t *testing.T) {
				testServerHijackBidirectionalStream(t, bidirectional, false, assert.AnError)
			})
		})
	}
}

func testServerHijackBidirectionalStream(t *testing.T, bidirectional bool, doHijack bool, hijackErr error) {
	id := quic.ConnectionTracingID(1337)
	type hijackCall struct {
		ft            FrameType  // for bidirectional streams
		st            StreamType // for unidirectional streams
		connTracingID quic.ConnectionTracingID
		e             error
	}
	hijackChan := make(chan hijackCall, 1)
	testDone := make(chan struct{})
	s := &Server{
		TLSConfig: testdata.GetTLSConfig(),
		StreamHijacker: func(ft FrameType, connTracingID quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
			defer close(testDone)
			hijackChan <- hijackCall{ft: ft, connTracingID: connTracingID, e: e}
			return doHijack, hijackErr
		},
		UniStreamHijacker: func(st StreamType, connTracingID quic.ConnectionTracingID, _ quic.ReceiveStream, err error) bool {
			defer close(testDone)
			hijackChan <- hijackCall{st: st, connTracingID: connTracingID, e: err}
			return doHijack
		},
	}
	s.init()

	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
	mockCtrl := gomock.NewController(t)
	unknownStr := mockquic.NewMockStream(mockCtrl)
	unknownStr.EXPECT().Context().Return(context.Background()).AnyTimes()
	unknownStr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	unknownStr.EXPECT().StreamID().AnyTimes()
	if !doHijack || hijackErr != nil {
		if bidirectional {
			unknownStr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
			unknownStr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		} else {
			unknownStr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeStreamCreationError))
		}
	}
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	if bidirectional {
		conn.EXPECT().AcceptStream(gomock.Any()).Return(unknownStr, nil)
	} else {
		conn.EXPECT().AcceptUniStream(gomock.Any()).Return(unknownStr, nil)
	}
	conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
		<-testDone
		return nil, assert.AnError
	})
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any())
	conn.EXPECT().OpenUniStream().Return(controlStr, nil)
	conn.EXPECT().RemoteAddr().Return(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1337}).AnyTimes()
	conn.EXPECT().LocalAddr().AnyTimes()
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-testDone
		return nil, assert.AnError
	})
	ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, id)
	conn.EXPECT().Context().Return(ctx).AnyTimes()
	s.handleConn(conn)
	select {
	case hijackCall := <-hijackChan:
		if bidirectional {
			assert.Zero(t, hijackCall.st)
			assert.Equal(t, hijackCall.ft, FrameType(0x41))
		} else {
			assert.Equal(t, hijackCall.st, StreamType(0x41))
			assert.Zero(t, hijackCall.ft)
		}
		assert.Equal(t, hijackCall.connTracingID, id)
		assert.NoError(t, hijackCall.e)
	case <-time.After(time.Second):
		t.Fatal("hijack call not received")
	}

	time.Sleep(scaleDuration(20 * time.Millisecond)) // don't EXPECT any calls to conn.CloseWithError
}

func getAltSvc(s *Server) (string, bool) {
	hdr := http.Header{}
	s.SetQUICHeaders(hdr)
	if altSvc, ok := hdr["Alt-Svc"]; ok {
		return altSvc[0], true
	}
	return "", false
}

func TestServerAltSvcFromListenersAndConns(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		testServerAltSvcFromListenersAndConns(t, []quic.Version{})
	})
	t.Run("v1", func(t *testing.T) {
		testServerAltSvcFromListenersAndConns(t, []quic.Version{quic.Version1})
	})
	t.Run("v1 and v2", func(t *testing.T) {
		testServerAltSvcFromListenersAndConns(t, []quic.Version{quic.Version1, quic.Version2})
	})
}

func testServerAltSvcFromListenersAndConns(t *testing.T, versions []quic.Version) {
	ln1, err := quic.ListenEarly(newUDPConnLocalhost(t), testdata.GetTLSConfig(), nil)
	require.NoError(t, err)
	port1 := ln1.Addr().(*net.UDPAddr).Port

	s := &Server{
		Addr:       ":1337", // will be ignored since we're using listeners
		TLSConfig:  testdata.GetTLSConfig(),
		QUICConfig: &quic.Config{Versions: versions},
	}
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		s.ServeListener(ln1)
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))
	altSvc, ok := getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf(`h3=":%d"; ma=2592000`, port1), altSvc)

	udpConn := newUDPConnLocalhost(t)
	port2 := udpConn.LocalAddr().(*net.UDPAddr).Port
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		s.Serve(udpConn)
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))
	altSvc, ok = getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf(`h3=":%d"; ma=2592000,h3=":%d"; ma=2592000`, port1, port2), altSvc)

	// Close the first listener.
	// This should remove the associated Alt-Svc entry.
	require.NoError(t, ln1.Close())
	select {
	case <-done1:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	altSvc, ok = getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf(`h3=":%d"; ma=2592000`, port2), altSvc)

	// Close the second listener.
	// This should remove the Alt-Svc entry altogether.
	require.NoError(t, udpConn.Close())
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	_, ok = getAltSvc(s)
	require.False(t, ok)
}

func TestServerAltSvcFromPort(t *testing.T) {
	s := &Server{Port: 1337}
	_, ok := getAltSvc(s)
	require.False(t, ok)

	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), testdata.GetTLSConfig(), nil)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeListener(ln)
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))

	altSvc, ok := getAltSvc(s)
	require.True(t, ok)
	require.Equal(t, `h3=":1337"; ma=2592000`, altSvc)

	require.NoError(t, ln.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	_, ok = getAltSvc(s)
	require.False(t, ok)
}

type unixSocketListener struct {
	*quic.EarlyListener
}

func (l *unixSocketListener) Addr() net.Addr {
	return &net.UnixAddr{Net: "unix", Name: "/tmp/quic.sock"}
}

func TestServerAltSvcFromUnixSocket(t *testing.T) {
	t.Run("with Server.Addr not set", func(t *testing.T) {
		_, ok := testServerAltSvcFromUnixSocket(t, "")
		require.False(t, ok)
	})

	t.Run("with Server.Addr set", func(t *testing.T) {
		altSvc, ok := testServerAltSvcFromUnixSocket(t, ":1337")
		require.True(t, ok)
		require.Equal(t, `h3=":1337"; ma=2592000`, altSvc)
	})
}

func testServerAltSvcFromUnixSocket(t *testing.T, addr string) (altSvc string, ok bool) {
	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), testdata.GetTLSConfig(), nil)
	require.NoError(t, err)

	var logBuf bytes.Buffer
	s := &Server{
		Addr:   addr,
		Logger: slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeListener(&unixSocketListener{EarlyListener: ln})
	}()
	time.Sleep(scaleDuration(10 * time.Millisecond))

	altSvc, ok = getAltSvc(s)
	require.NoError(t, ln.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Contains(t, logBuf.String(), "Unable to extract port from listener, will not be announced using SetQUICHeaders")
	return altSvc, ok
}

func TestServerListenAndServeErrors(t *testing.T) {
	require.EqualError(t, (&Server{}).ListenAndServe(), "use of http3.Server without TLSConfig")
	s := &Server{
		Addr:      ":123456",
		TLSConfig: testdata.GetTLSConfig(),
	}
	require.ErrorContains(t, s.ListenAndServe(), "invalid port")
}

func TestServerClosing(t *testing.T) {
	s := &Server{TLSConfig: testdata.GetTLSConfig()}
	require.NoError(t, s.Close())
	require.NoError(t, s.Close()) // duplicate calls are ok
	require.ErrorIs(t, s.ListenAndServe(), http.ErrServerClosed)
	require.ErrorIs(t, s.ListenAndServeTLS(testdata.GetCertificatePaths()), http.ErrServerClosed)
	require.ErrorIs(t, s.Serve(nil), http.ErrServerClosed)
	require.ErrorIs(t, s.ServeListener(nil), http.ErrServerClosed)
	require.ErrorIs(t, s.ServeQUICConn(nil), http.ErrServerClosed)
}

func TestHandlesConcurrentServeAndClose(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	require.NoError(t, err)
	c, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	done := make(chan struct{})
	s := &Server{TLSConfig: testdata.GetTLSConfig()}
	go func() {
		defer close(done)
		s.Serve(c)
	}()
	runtime.Gosched()
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
