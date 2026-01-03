package http3

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestClientSettings(t *testing.T) {
	t.Run("enable datagrams", func(t *testing.T) {
		testClientSettings(t, true, nil)
	})
	t.Run("additional settings", func(t *testing.T) {
		testClientSettings(t, false, map[uint64]uint64{13: 37})
	})
}

func testClientSettings(t *testing.T, enableDatagrams bool, other map[uint64]uint64) {
	tr := &Transport{
		EnableDatagrams:    enableDatagrams,
		AdditionalSettings: other,
	}

	var eventRecorder events.Recorder
	clientConn, serverConn := newConnPair(t, withClientRecorder(&eventRecorder))
	tr.NewClientConn(clientConn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	str.SetReadDeadline(time.Now().Add(time.Second))
	typ, err := quicvarint.Read(quicvarint.NewReader(str))
	require.NoError(t, err)
	require.EqualValues(t, streamTypeControlStream, typ)
	fp := (&frameParser{r: str})
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	settingsFrame := f.(*settingsFrame)
	require.Equal(t, settingsFrame.Datagram, enableDatagrams)
	require.Equal(t, settingsFrame.Other, other)

	var datagramValue *bool
	if enableDatagrams {
		datagramValue = pointer(true)
	}
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameCreated{
				StreamID: str.StreamID(),
				Raw:      qlog.RawInfo{Length: 10},
				Frame: qlog.Frame{
					Frame: qlog.SettingsFrame{
						MaxFieldSectionSize: defaultMaxResponseHeaderBytes,
						Datagram:            datagramValue,
						Other:               other,
					},
				},
			},
		},
		filterQlogEventsForFrame(eventRecorder.Events(qlog.FrameCreated{}), qlog.SettingsFrame{}),
	)
}

func encodeResponse(t *testing.T, status int) []byte {
	t.Helper()

	mockCtrl := gomock.NewController(t)
	buf := &bytes.Buffer{}
	rstr := NewMockDatagramStream(mockCtrl)
	rstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil), nil, false, nil)
	rw.WriteHeader(status)
	rw.Flush()
	return buf.Bytes()
}

func TestClientRequest(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		rsp := testClientRequest(t, false, http.MethodGet, encodeResponse(t, http.StatusTeapot))
		require.Equal(t, http.StatusTeapot, rsp.StatusCode)
		require.Equal(t, "HTTP/3.0", rsp.Proto)
		require.Equal(t, 3, rsp.ProtoMajor)
		require.NotNil(t, rsp.Request)
	})

	t.Run("GET 0-RTT", func(t *testing.T) {
		rsp := testClientRequest(t, true, http.MethodGet, encodeResponse(t, http.StatusOK))
		require.Equal(t, http.StatusOK, rsp.StatusCode)
	})

	t.Run("HEAD", func(t *testing.T) {
		rsp := testClientRequest(t, false, http.MethodHead, encodeResponse(t, http.StatusTeapot))
		require.Equal(t, http.StatusTeapot, rsp.StatusCode)
	})

	t.Run("HEAD 0-RTT", func(t *testing.T) {
		rsp := testClientRequest(t, true, http.MethodHead, encodeResponse(t, http.StatusOK))
		require.Equal(t, http.StatusOK, rsp.StatusCode)
	})
}

func testClientRequest(t *testing.T, use0RTT bool, method string, rspBytes []byte) *http.Response {
	clientConn, serverConn := newConnPair(t)

	reqMethod := method
	if use0RTT {
		switch method {
		case http.MethodGet:
			reqMethod = MethodGet0RTT
		case http.MethodHead:
			reqMethod = MethodHead0RTT
		}
	}
	req, err := http.NewRequest(reqMethod, "http://quic-go.net", nil)
	require.NoError(t, err)

	type result struct {
		rsp *http.Response
		err error
	}
	resultChan := make(chan result, 1)
	go func() {
		cc := (&Transport{}).NewClientConn(clientConn)
		rsp, err := cc.RoundTrip(req)
		resultChan <- result{rsp: rsp, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	str.SetReadDeadline(time.Now().Add(time.Second))

	hfs := decodeHeader(t, str)
	require.Equal(t, []string{method}, hfs[":method"])

	_, err = str.Write(rspBytes)
	require.NoError(t, err)

	var res result
	select {
	case res = <-resultChan:
		require.NoError(t, res.err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// make sure the http.Request.Method value was not modified
	if use0RTT {
		switch reqMethod {
		case MethodGet0RTT:
			require.Equal(t, req.Method, MethodGet0RTT)
		case MethodHead0RTT:
			require.Equal(t, req.Method, MethodHead0RTT)
		}
	}
	return res.rsp
}

func randomString(length int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n := mrand.IntN(len(alphabet))
		b[i] = alphabet[n]
	}
	return string(b)
}

func TestClientRequestError(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	req, err := http.NewRequest(http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)
	for range 1000 {
		req.Header.Add(randomString(50), randomString(50))
	}

	type result struct {
		rsp *http.Response
		err error
	}
	resultChan := make(chan result, 1)
	go func() {
		cc := (&Transport{}).NewClientConn(clientConn)
		rsp, err := cc.RoundTrip(req)
		resultChan <- result{rsp: rsp, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	str.CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))

	_, err = str.Write(encodeResponse(t, http.StatusTeapot))
	require.NoError(t, err)

	var res result
	select {
	case res = <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, http.StatusTeapot, res.rsp.StatusCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestClientResponseValidation(t *testing.T) {
	t.Run("HEADERS frame too large", func(t *testing.T) {
		require.ErrorContains(t,
			testClientResponseValidation(t,
				&Transport{MaxResponseHeaderBytes: 1337},
				(&headersFrame{Length: 1338}).Append(nil),
				quic.StreamErrorCode(ErrCodeFrameError),
			),
			"http3: HEADERS frame too large",
		)
	})

	t.Run("invalid headers", func(t *testing.T) {
		headerBuf := &bytes.Buffer{}
		enc := qpack.NewEncoder(headerBuf)
		// not a valid response pseudo header
		require.NoError(t, enc.WriteField(qpack.HeaderField{Name: ":method", Value: "GET"}))
		require.NoError(t, enc.Close())
		b := (&headersFrame{Length: uint64(headerBuf.Len())}).Append(nil)
		b = append(b, headerBuf.Bytes()...)

		require.ErrorContains(t,
			testClientResponseValidation(t, &Transport{}, b, quic.StreamErrorCode(ErrCodeMessageError)),
			"invalid response pseudo header",
		)
	})
}

func testClientResponseValidation(t *testing.T, tr *Transport, rsp []byte, expectedReset quic.StreamErrorCode) error {
	clientConn, serverConn := newConnPair(t)

	cc := tr.NewClientConn(clientConn)
	errChan := make(chan error)
	go func() {
		_, err := cc.RoundTrip(httptest.NewRequest(http.MethodGet, "http://quic-go.net", nil))
		errChan <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	_, err = str.Write(rsp)
	require.NoError(t, err)

	select {
	case err := <-errChan:
		expectStreamWriteReset(t, str, expectedReset)
		// The client closes the stream after sending the request,
		// so we need to wait for the RESET_STREAM frame to be received.
		time.Sleep(scaleDuration(10 * time.Millisecond))
		expectStreamReadReset(t, str, expectedReset)
		return err
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	panic("unreachable")
}

func TestClientRequestLengthLimit(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	cc := (&Transport{}).NewClientConn(clientConn)
	errChan := make(chan error)
	body := bytes.NewBufferString("request body")
	go func() {
		req := httptest.NewRequest(http.MethodPost, "http://quic-go.net", body)
		req.ContentLength = 8
		_, err := cc.RoundTrip(req)
		errChan <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)

	_, err = io.ReadAll(str)
	var strErr *quic.StreamError
	require.ErrorAs(t, err, &strErr)
	require.Equal(t, quic.StreamErrorCode(ErrCodeRequestCanceled), strErr.ErrorCode)

	_, err = str.Write(encodeResponse(t, http.StatusTeapot))
	require.NoError(t, err)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestClientExtendedConnect(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		testClientExtendedConnect(t, true)
	})

	t.Run("disabled", func(t *testing.T) {
		testClientExtendedConnect(t, false)
	})
}

func testClientExtendedConnect(t *testing.T, enabled bool) {
	clientConn, serverConn := newConnPair(t)

	cc := (&Transport{}).NewClientConn(clientConn)
	req, err := http.NewRequest(http.MethodConnect, "http://quic-go.net", nil)
	require.NoError(t, err)
	req.Proto = "connect"

	errChan := make(chan error)
	go func() {
		_, err := cc.RoundTrip(req)
		errChan <- err
	}()

	select {
	case <-errChan:
		t.Fatal("RoundTrip should have blocked until SETTINGS were received")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// now send the SETTINGS
	settingsStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	settingsStr.SetWriteDeadline(time.Now().Add(time.Second))
	settingsFrame := &settingsFrame{ExtendedConnect: enabled}
	_, err = settingsStr.Write(settingsFrame.Append(quicvarint.Append(nil, streamTypeControlStream)))
	require.NoError(t, err)

	select {
	case <-cc.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	settings := cc.Settings()
	require.Equal(t, enabled, settings.EnableExtendedConnect)

	if enabled {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		str, err := serverConn.AcceptStream(ctx)
		require.NoError(t, err)
		str.CancelRead(1337)
		str.CancelWrite(1337)
	}

	select {
	case err := <-errChan:
		if enabled {
			require.ErrorIs(t, err, &Error{Remote: true, ErrorCode: 1337})
		} else {
			require.EqualError(t, err, "http3: server didn't enable Extended CONNECT")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestClient1xxHandling(t *testing.T) {
	t.Run("a few early hints", func(t *testing.T) {
		testClient1xxHandling(t, max1xxResponses, http.StatusOK, false)
	})
	t.Run("too many early hints", func(t *testing.T) {
		testClient1xxHandling(t, max1xxResponses+1, http.StatusOK, true)
	})
	t.Run("EarlyHints followed by StatusSwitchingProtocols", func(t *testing.T) {
		testClient1xxHandling(t, 1, http.StatusSwitchingProtocols, false)
	})
}

func testClient1xxHandling(t *testing.T, numEarlyHints int, terminalStatus int, tooMany bool) {
	var rspBuf bytes.Buffer
	rstr := NewMockDatagramStream(gomock.NewController(t))
	rstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	rstr.EXPECT().Write(gomock.Any()).Do(rspBuf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil), nil, false, nil)
	rw.header.Add("Link", "foo")
	rw.header.Add("Link", "bar")
	for range numEarlyHints {
		rw.WriteHeader(http.StatusEarlyHints)
	}
	rw.WriteHeader(terminalStatus)
	rw.Flush()
	rspBytes := rspBuf.Bytes()

	clientConn, serverConn := newConnPair(t)

	type result struct {
		rsp *http.Response
		err error
	}
	resultChan := make(chan result, 1)
	go func() {
		cc := (&Transport{}).NewClientConn(clientConn)
		rsp, err := cc.RoundTrip(httptest.NewRequest(http.MethodGet, "http://quic-go.net", nil))
		resultChan <- result{rsp: rsp, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)

	// request headers
	hfs := decodeHeader(t, str)
	require.Equal(t, hfs[":method"], []string{http.MethodGet})

	_, err = str.Write(rspBytes)
	require.NoError(t, err)

	var rsp *http.Response
	select {
	case res := <-resultChan:
		if tooMany {
			require.EqualError(t, res.err, "http3: too many 1xx informational responses")
			return
		}
		require.NoError(t, res.err)
		rsp = res.rsp
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Equal(t, []string{"foo", "bar"}, rsp.Header["Link"])
	require.Equal(t, terminalStatus, rsp.StatusCode)
}

func TestClientGzip(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte("foobar"))
	w.Close()
	gzippedFoobar := buf.Bytes()

	t.Run("gzipped", func(t *testing.T) {
		testClientGzip(t, gzippedFoobar, []byte("foobar"), false, true)
	})
	t.Run("not gzipped", func(t *testing.T) {
		testClientGzip(t, []byte("foobar"), []byte("foobar"), false, false)
	})
	t.Run("disable compression", func(t *testing.T) {
		testClientGzip(t, gzippedFoobar, gzippedFoobar, true, true)
	})
}

func testClientGzip(t *testing.T,
	data []byte,
	expectedRsp []byte,
	transportDisableCompression bool,
	responseAddContentEncoding bool,
) {
	var rspBuf bytes.Buffer
	rstr := NewMockDatagramStream(gomock.NewController(t))
	rstr.EXPECT().StreamID().Return(quic.StreamID(42)).AnyTimes()
	rstr.EXPECT().Write(gomock.Any()).Do(rspBuf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, nil, func(io.Reader, *headersFrame) error { return nil }, nil), nil, false, nil)
	rw.WriteHeader(http.StatusOK)
	if responseAddContentEncoding {
		rw.header.Add("Content-Encoding", "gzip")
	}
	rw.Write(data)
	rw.Flush()

	clientConn, serverConn := newConnPair(t)

	type result struct {
		rsp *http.Response
		err error
	}
	resultChan := make(chan result)
	go func() {
		cc := (&Transport{DisableCompression: transportDisableCompression}).NewClientConn(clientConn)
		rsp, err := cc.RoundTrip(httptest.NewRequest(http.MethodGet, "http://quic-go.net", nil))
		resultChan <- result{rsp: rsp, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)

	// request headers
	str.SetReadDeadline(time.Now().Add(time.Second))
	hfs := decodeHeader(t, str)
	if transportDisableCompression {
		require.NotContains(t, hfs, "accept-encoding")
	} else {
		require.Equal(t, hfs["accept-encoding"], []string{"gzip"})
	}

	_, err = str.Write(rspBuf.Bytes())
	require.NoError(t, err)
	require.NoError(t, str.Close())

	var rsp *http.Response
	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		rsp = res.rsp
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Equal(t, http.StatusOK, rsp.StatusCode)
	body, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, expectedRsp, body)
}

func TestClientRequestCancellation(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	requestCtx, requestCancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)

	type result struct {
		rsp *http.Response
		err error
	}
	resultChan := make(chan result)
	go func() {
		cc := (&Transport{}).NewClientConn(clientConn)
		rsp, err := cc.RoundTrip(req)
		resultChan <- result{rsp: rsp, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	str, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)

	_, err = str.Write(encodeResponse(t, http.StatusTeapot))
	require.NoError(t, err)

	select {
	case res := <-resultChan:
		require.NoError(t, res.err)
		require.Equal(t, http.StatusTeapot, res.rsp.StatusCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	requestCancel()

	expectStreamWriteReset(t, str, quic.StreamErrorCode(ErrCodeRequestCanceled))
}

func TestClientConnGoAway(t *testing.T) {
	t.Run("no active streams", func(t *testing.T) {
		testClientConnGoAway(t, false)
	})

	t.Run("active stream", func(t *testing.T) {
		testClientConnGoAway(t, true)
	})
}

func testClientConnGoAway(t *testing.T, withStream bool) {
	var clientEventRecorder events.Recorder
	clientConn, serverConn := newConnPair(t, withClientRecorder(&clientEventRecorder))

	cc := (&Transport{}).NewClientConn(clientConn)

	var str *RequestStream
	if withStream {
		s, err := cc.OpenRequestStream(context.Background())
		require.NoError(t, err)
		str = s
	}

	// server sends control stream with SETTINGS and GOAWAY
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	b = (&goAwayFrame{StreamID: 8}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	// the connection should be closed after the stream is closed
	if withStream {
		select {
		case <-serverConn.Context().Done():
			t.Fatal("connection closed")
		case <-time.After(scaleDuration(10 * time.Millisecond)):
		}

		// the stream ID in the GOAWAY frame is 8, so it's possible to open stream 4
		str2, err := cc.OpenRequestStream(context.Background())
		require.NoError(t, err)
		str2.Close()
		str2.CancelRead(1337)

		// it's not possible to open stream 8
		_, err = cc.OpenRequestStream(context.Background())
		require.ErrorIs(t, err, errGoAway)

		str.Close()
		str.CancelRead(1337)
	}

	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeNoError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}

	expectedLen, expectedPayloadLen := expectedFrameLength(t, &goAwayFrame{StreamID: 8})
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.FrameParsed{
				StreamID: controlStr.StreamID(),
				Raw:      qlog.RawInfo{PayloadLength: expectedPayloadLen, Length: expectedLen},
				Frame:    qlog.Frame{Frame: qlog.GoAwayFrame{StreamID: 8}},
			},
		},
		filterQlogEventsForFrame(clientEventRecorder.Events(qlog.FrameParsed{}), qlog.GoAwayFrame{StreamID: 8}),
	)
}

func TestClientConnGoConcurrent(t *testing.T) {
	clientConn, serverConn := newConnPair(t, withServerBidiStreamLimit(1)) // allows streams 0

	cc := (&Transport{}).NewClientConn(clientConn)

	// peer sends control stream with SETTINGS, but not GOAWAY yet
	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	controlStr, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	select {
	case <-serverConn.Context().Done():
		t.Fatal("connection closed")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// of these 2 OpenStreamSync calls, one will succeed, the other one will block
	errChan := make(chan error, 3)
	for range 2 {
		go func() {
			str, err := cc.OpenRequestStream(context.Background())
			if err == nil {
				str.Close()
			}
			errChan <- err
		}()
	}

	// wait until all Goroutines have started
	time.Sleep(scaleDuration(10 * time.Millisecond))

	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	// the second stream is still blocked
	select {
	case <-errChan:
		t.Fatal("second OpenStreamSync should have blocked")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// send the GOAWAY frame
	b = (&goAwayFrame{StreamID: 4}).Append(nil)
	_, err = controlStr.Write(b)
	require.NoError(t, err)

	// accepting and closing the stream allows the client to open another stream
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sstr, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	sstr.Close()
	sstr.CancelRead(1337)

	// The second stream is opened by the client,
	// and immediately closed with a H3_REQUEST_CANCELED error.
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, errGoAway)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
		t.Fatal("timeout")
	}

	sstr, err = serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	_, err = sstr.Read([]byte{0})
	require.ErrorIs(t, err, &quic.StreamError{StreamID: 4, ErrorCode: quic.StreamErrorCode(ErrCodeRequestCanceled), Remote: true})
}

func TestClientConnGoAwayFailures(t *testing.T) {
	t.Run("invalid frame", func(t *testing.T) {
		b := (&settingsFrame{}).Append(nil)
		// 1337 is invalid value for the Extended CONNECT setting
		b = (&settingsFrame{Other: map[uint64]uint64{settingExtendedConnect: 1337}}).Append(b)
		testClientConnGoAwayFailures(t, b, nil, ErrCodeFrameError)
	})

	t.Run("not a GOAWAY", func(t *testing.T) {
		b := (&settingsFrame{}).Append(nil)
		// GOAWAY is the only allowed frame type after SETTINGS
		b = (&headersFrame{}).Append(b)
		testClientConnGoAwayFailures(t, b, nil, ErrCodeFrameUnexpected)
	})

	t.Run("stream closed before GOAWAY", func(t *testing.T) {
		testClientConnGoAwayFailures(t, (&settingsFrame{}).Append(nil), io.EOF, ErrCodeClosedCriticalStream)
	})

	t.Run("stream reset before GOAWAY", func(t *testing.T) {
		testClientConnGoAwayFailures(t,
			(&settingsFrame{}).Append(nil),
			&quic.StreamError{Remote: true, ErrorCode: 42},
			ErrCodeClosedCriticalStream,
		)
	})

	t.Run("invalid stream ID", func(t *testing.T) {
		data := (&settingsFrame{}).Append(nil)
		data = (&goAwayFrame{StreamID: 1}).Append(data)
		testClientConnGoAwayFailures(t, data, nil, ErrCodeIDError)
	})

	t.Run("increased stream ID", func(t *testing.T) {
		localConn, peerConn := newConnPair(t)

		cc := (&Transport{}).NewClientConn(localConn)

		// need an active stream so the connection doesn't close after the first GOAWAY
		_, err := cc.OpenRequestStream(context.Background())
		require.NoError(t, err)

		controlStr, err := peerConn.OpenUniStream()
		require.NoError(t, err)
		b := quicvarint.Append(nil, streamTypeControlStream)
		b = (&settingsFrame{}).Append(b)
		b = (&goAwayFrame{StreamID: 4}).Append(b)
		b = (&goAwayFrame{StreamID: 8}).Append(b)
		_, err = controlStr.Write(b)
		require.NoError(t, err)

		select {
		case <-peerConn.Context().Done():
			require.ErrorIs(t,
				context.Cause(peerConn.Context()),
				&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeIDError)},
			)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for close")
		}
	})
}

func testClientConnGoAwayFailures(t *testing.T, data []byte, readErr error, expectedErr ErrCode) {
	localConn, peerConn := newConnPair(t)

	(&Transport{}).NewClientConn(localConn)

	controlStr, err := peerConn.OpenUniStream()
	require.NoError(t, err)
	_, err = controlStr.Write(quicvarint.Append(nil, streamTypeControlStream))
	require.NoError(t, err)

	switch readErr {
	case nil:
		_, err = controlStr.Write(data)
		require.NoError(t, err)
	case io.EOF:
		_, err = controlStr.Write(data)
		require.NoError(t, err)
		require.NoError(t, controlStr.Close())
	default:
		// make sure the stream type is received
		time.Sleep(scaleDuration(10 * time.Millisecond))
		controlStr.CancelWrite(1337)
	}

	select {
	case <-peerConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(peerConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(expectedErr)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for close")
	}
}

func TestClientConnHandleBidirectionalStream(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	cc := (&Transport{}).NewClientConn(clientConn)

	str, err := clientConn.OpenStream()
	require.NoError(t, err)
	cc.HandleBidirectionalStream(str)

	select {
	case <-serverConn.Context().Done():
		require.ErrorIs(t,
			context.Cause(serverConn.Context()),
			&quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(ErrCodeStreamCreationError)},
		)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for connection close")
	}
}

func TestRawClientConnHandleUnidirectionalStream(t *testing.T) {
	clientConn, serverConn := newConnPair(t)

	cc := (&Transport{}).NewRawClientConn(clientConn)

	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{}).Append(b)
	str, err := serverConn.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(b)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	uniStr, err := clientConn.AcceptUniStream(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		cc.HandleUnidirectionalStream(uniStr)
	}()

	select {
	case <-cc.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	require.NotNil(t, cc.Settings())
}
