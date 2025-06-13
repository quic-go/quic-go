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

	"github.com/Noooste/uquic-go"
	"github.com/Noooste/uquic-go/internal/testdata"
	"github.com/Noooste/uquic-go/quicvarint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	clientConn, serverConn := newConnPair(t)
	go s.handleConn(serverConn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	settingsStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	settingsStr.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1024)
	n, err := settingsStr.Read(b)
	require.NoError(t, err)
	b = b[:n]

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

func testServerRequestHandling(t *testing.T,
	handler http.HandlerFunc,
	req *http.Request,
) (responseHeaders map[string][]string, body []byte) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, req))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	s := &Server{Handler: handler}
	go s.ServeQUICConn(serverConn)

	hfs := decodeHeader(t, str)
	fp := frameParser{r: str}
	var content []byte
	for {
		frame, err := fp.ParseNext()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		require.IsType(t, &dataFrame{}, frame)
		b := make([]byte, frame.(*dataFrame).Length)
		_, err = io.ReadFull(str, b)
		require.NoError(t, err)
		content = append(content, b...)
	}
	return hfs, content
}

func TestServerFirstFrameNotHeaders(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)

	var buf bytes.Buffer
	buf.Write((&dataFrame{Length: 6}).Append(nil))
	buf.Write([]byte("foobar"))
	_, err = str.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, str.Close())

	s := &Server{}
	go s.ServeQUICConn(serverConn)

	select {
	case <-clientConn.Context().Done():
		err := context.Cause(clientConn.Context())
		var appErr *quic.ApplicationError
		require.ErrorAs(t, err, &appErr)
		require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameUnexpected), appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
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

func testServerHandlerBodyNotRead(t *testing.T, req *http.Request, handler http.HandlerFunc) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, req))
	require.NoError(t, err)
	// require.NoError(t, str.Close())

	done := make(chan struct{})
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(done)
			handler(w, r)
		}),
	}

	go s.ServeQUICConn(serverConn)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServerStreamResetByClient(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	str.CancelWrite(1337)

	var called bool
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}),
	}

	go s.ServeQUICConn(serverConn)

	expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeRequestIncomplete))
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
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	var logBuf bytes.Buffer
	s := &Server{
		Handler: handler,
		Logger:  slog.New(slog.NewTextHandler(&logBuf, nil)),
	}

	go s.ServeQUICConn(serverConn)

	expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeInternalError))
	s.Close()

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
		MaxHeaderBytes: maxHeaderBytes,
		Handler:        http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
	}
	s.init()

	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, req))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	go s.ServeQUICConn(serverConn)

	expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeFrameError))
	expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeFrameError))

	require.False(t, called)
}

func TestServerRequestContext(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)))
	require.NoError(t, err)

	ctxChan := make(chan context.Context, 1)
	block := make(chan struct{})
	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctxChan <- r.Context()
			<-block
		}),
	}

	go s.ServeQUICConn(serverConn)

	var requestContext context.Context
	select {
	case requestContext = <-ctxChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Equal(t, s, requestContext.Value(ServerContextKey))
	require.Equal(t, serverConn.LocalAddr(), requestContext.Value(http.LocalAddrContextKey))
	require.Equal(t, serverConn.RemoteAddr(), requestContext.Value(RemoteAddrContextKey))
	select {
	case <-requestContext.Done():
		t.Fatal("request context was canceled")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	str.CancelRead(1337)

	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	require.Equal(t, context.Canceled, requestContext.Err())
	close(block)
}

func TestServerHTTPStreamHijacking(t *testing.T) {
	clientConn, serverConn := newConnPair(t)
	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodHead, "https://www.example.com", nil)))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	s := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			str := w.(HTTPStreamer).HTTPStream()
			str.Write([]byte("foobar"))
			str.Close()
		}),
	}
	go s.ServeQUICConn(serverConn)

	str.SetReadDeadline(time.Now().Add(time.Second))
	rsp, err := io.ReadAll(str)
	require.NoError(t, err)
	r := bytes.NewReader(rsp)
	hfs := decodeHeader(t, r)
	require.Equal(t, hfs[":status"], []string{"200"})
	fp := frameParser{r: r}
	frame, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, frame)
	dataFrame := frame.(*dataFrame)
	require.Equal(t, uint64(6), dataFrame.Length)
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), data)
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
	type hijackCall struct {
		ft            FrameType  // for bidirectional streams
		st            StreamType // for unidirectional streams
		connTracingID quic.ConnectionTracingID
		e             error
	}
	hijackChan := make(chan hijackCall, 1)
	testDone := make(chan struct{})
	s := &Server{
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

	clientConn, serverConn := newConnPair(t)
	go s.ServeQUICConn(serverConn)

	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
	if bidirectional {
		str, err := clientConn.OpenStream()
		require.NoError(t, err)
		_, err = str.Write(buf.Bytes())
		require.NoError(t, err)

		if hijackErr != nil {
			expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeRequestIncomplete))
			expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeRequestIncomplete))
		}
		// if the stream is not hijacked, the frame parser will skip the frame
	} else {
		str, err := clientConn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write(buf.Bytes())
		require.NoError(t, err)

		if !doHijack || hijackErr != nil {
			expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeStreamCreationError))
		}
	}

	select {
	case hijackCall := <-hijackChan:
		if bidirectional {
			assert.Zero(t, hijackCall.st)
			assert.Equal(t, hijackCall.ft, FrameType(0x41))
		} else {
			assert.Equal(t, hijackCall.st, StreamType(0x41))
			assert.Zero(t, hijackCall.ft)
		}
		assert.Equal(t, serverConn.Context().Value(quic.ConnectionTracingKey), hijackCall.connTracingID)
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
	ln1, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), nil)
	require.NoError(t, err)
	port1 := ln1.Addr().(*net.UDPAddr).Port

	s := &Server{
		Addr:       ":1337", // will be ignored since we're using listeners
		TLSConfig:  getTLSConfig(),
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

	ln, err := quic.ListenEarly(newUDPConnLocalhost(t), getTLSConfig(), nil)
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
	s := &Server{TLSConfig: getTLSConfig()}
	require.NoError(t, s.Close())
	require.NoError(t, s.Close()) // duplicate calls are ok
	require.ErrorIs(t, s.ListenAndServe(), http.ErrServerClosed)
	require.ErrorIs(t, s.ListenAndServeTLS(testdata.GetCertificatePaths()), http.ErrServerClosed)
	require.ErrorIs(t, s.Serve(nil), http.ErrServerClosed)
	require.ErrorIs(t, s.ServeListener(nil), http.ErrServerClosed)
	require.ErrorIs(t, s.ServeQUICConn(nil), http.ErrServerClosed)
}

func TestServerConcurrentServeAndClose(t *testing.T) {
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

func TestServerImmediateGracefulShutdown(t *testing.T) {
	s := &Server{TLSConfig: testdata.GetTLSConfig()}
	errChan := make(chan error, 1)
	go func() { errChan <- s.Shutdown(context.Background()) }()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestServerGracefulShutdown(t *testing.T) {
	requestChan := make(chan struct{}, 1)
	s := &Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestChan <- struct{}{}
	})}

	clientConn, serverConn := newConnPair(t)
	go s.ServeQUICConn(serverConn)

	firstStream, err := clientConn.OpenStream()
	require.NoError(t, err)
	_, err = firstStream.Write(encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)))
	require.NoError(t, err)

	select {
	case <-requestChan:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	controlStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)
	typ, err := quicvarint.Read(quicvarint.NewReader(controlStr))
	require.NoError(t, err)
	require.EqualValues(t, streamTypeControlStream, typ)
	fp := &frameParser{r: controlStr}
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	errChan := make(chan error)
	go func() {
		errChan <- s.Shutdown(shutdownCtx)
	}()

	f, err = fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, &goAwayFrame{StreamID: 4}, f)

	select {
	case <-errChan:
		t.Fatal("didn't expect Shutdown to return")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// all further streams are getting rejected
	for range 3 {
		str, err := clientConn.OpenStream()
		require.NoError(t, err)
		_, _ = str.Write(encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://www.example.com", nil)))
		expectStreamReadReset(t, str, quic.StreamErrorCode(ErrCodeRequestRejected))
		expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeRequestRejected))
	}

	// cancel the context passed to Shutdown
	shutdownCancel()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
