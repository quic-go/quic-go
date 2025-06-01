package http3

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Noooste/quic-go"
	"github.com/Noooste/quic-go/quicvarint"
	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/assert"
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

	clientConn, serverConn := newConnPair(t)
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
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.IsType(t, &settingsFrame{}, f)
	settingsFrame := f.(*settingsFrame)
	require.Equal(t, settingsFrame.Datagram, enableDatagrams)
	require.Equal(t, settingsFrame.Other, other)
}

func encodeResponse(t *testing.T, status int) []byte {
	mockCtrl := gomock.NewController(t)
	buf := &bytes.Buffer{}
	rstr := NewMockDatagramStream(mockCtrl)
	rstr.EXPECT().Write(gomock.Any()).Do(buf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
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
	rstr.EXPECT().Write(gomock.Any()).Do(rspBuf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
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
	rstr.EXPECT().Write(gomock.Any()).Do(rspBuf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
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

func TestClientStreamHijacking(t *testing.T) {
	t.Run("unidirectional", func(t *testing.T) {
		t.Run("hijacking", func(t *testing.T) {
			testClientStreamHijacking(t, false, true, nil)
		})
		t.Run("stream error", func(t *testing.T) {
			testClientStreamHijacking(t, false, false, assert.AnError)
		})
	})

	t.Run("bidirectional", func(t *testing.T) {
		t.Run("hijacking", func(t *testing.T) {
			testClientStreamHijacking(t, true, true, nil)
		})
		t.Run("stream error", func(t *testing.T) {
			testClientStreamHijacking(t, true, false, assert.AnError)
		})
	})
}

func testClientStreamHijacking(t *testing.T, bidirectional, doHijack bool, streamReadErr error) {
	type hijackCall struct {
		ft            FrameType  // for bidirectional streams
		st            StreamType // for unidirectional streams
		connTracingID quic.ConnectionTracingID
		e             error
	}

	hijackChan := make(chan hijackCall, 1)
	tr := &Transport{}
	switch bidirectional {
	case true:
		tr.StreamHijacker = func(ft FrameType, id quic.ConnectionTracingID, _ quic.Stream, e error) (hijacked bool, err error) {
			hijackChan <- hijackCall{ft: ft, connTracingID: id, e: e}
			if !doHijack {
				return false, errors.New("not hijacking")
			}
			return true, nil
		}
	case false:
		tr.UniStreamHijacker = func(st StreamType, id quic.ConnectionTracingID, rs quic.ReceiveStream, e error) (hijacked bool) {
			hijackChan <- hijackCall{st: st, connTracingID: id, e: e}
			return doHijack
		}
	}

	clientConn, serverConn := newConnPair(t)

	buf := bytes.NewBuffer(quicvarint.Append(nil, 0x41))
	if bidirectional {
		str, err := serverConn.OpenStream()
		require.NoError(t, err)
		_, err = str.Write(buf.Bytes())
		require.NoError(t, err)

		if streamReadErr != nil {
			str.CancelWrite(1337)
		}
	} else {
		str, err := serverConn.OpenUniStream()
		require.NoError(t, err)
		_, err = str.Write(buf.Bytes())
		require.NoError(t, err)

		if streamReadErr != nil {
			str.CancelWrite(1337)
		}
	}

	_ = tr.NewClientConn(clientConn)

	select {
	case hijackCall := <-hijackChan:
		assert.Equal(t, clientConn.Context().Value(quic.ConnectionTracingKey), hijackCall.connTracingID)
		if streamReadErr == nil {
			if bidirectional {
				assert.Equal(t, FrameType(0x41), hijackCall.ft)
			} else {
				assert.Equal(t, StreamType(0x41), hijackCall.st)
			}
			assert.NoError(t, hijackCall.e)
		} else {
			var strErr *quic.StreamError
			require.ErrorAs(t, hijackCall.e, &strErr)
			assert.Equal(t, quic.StreamErrorCode(1337), strErr.ErrorCode)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// if the stream is not hijacked, the frame parser will skip the frame
}
