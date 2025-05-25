package http3

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/quicvarint"

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

	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	var buf bytes.Buffer
	controlStr.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		buf.Write(b)
		close(done)
		return len(b), nil
	})
	conn.EXPECT().OpenUniStream().Return(controlStr, nil)

	tr.NewClientConn(conn)

	select {
	case <-done:
		b := buf.Bytes()
		typ, l, err := quicvarint.Parse(b)
		require.NoError(t, err)
		require.EqualValues(t, streamTypeControlStream, typ)
		fp := (&frameParser{r: bytes.NewReader(b[l:])})
		f, err := fp.ParseNext()
		require.NoError(t, err)
		require.IsType(t, &settingsFrame{}, f)
		settingsFrame := f.(*settingsFrame)
		require.Equal(t, settingsFrame.Datagram, enableDatagrams)
		require.Equal(t, settingsFrame.Other, other)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func closedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
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
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	if !use0RTT {
		conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	}
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	conn.EXPECT().ConnectionState()
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)

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

	var buf bytes.Buffer
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().Close()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(rspBytes).Read).AnyTimes()
	conn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)

	cc := (&Transport{}).NewClientConn(conn)
	rsp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	hfs := decodeHeader(t, &buf)
	require.Equal(t, []string{method}, hfs[":method"])

	// make sure the http.Request.Method value was not modified
	if use0RTT {
		switch reqMethod {
		case MethodGet0RTT:
			require.Equal(t, req.Method, MethodGet0RTT)
		case MethodHead0RTT:
			require.Equal(t, req.Method, MethodHead0RTT)
		}
	}
	return rsp
}

func TestClientResponseValidation(t *testing.T) {
	t.Run("HEADERS frame too large", func(t *testing.T) {
		testClientResponseValidation(t,
			&Transport{MaxResponseHeaderBytes: 1337},
			(&headersFrame{Length: 1338}).Append(nil),
			quic.StreamErrorCode(ErrCodeFrameError),
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

		testClientResponseValidation(t, &Transport{}, b, quic.StreamErrorCode(ErrCodeMessageError))
	})
}

func testClientResponseValidation(t *testing.T, tr *Transport, rsp []byte, expectedReset quic.StreamErrorCode) {
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)

	req, err := http.NewRequest(http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().CancelRead(expectedReset)
	str.EXPECT().CancelWrite(expectedReset)
	str.EXPECT().Close()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(rsp).Read).AnyTimes()
	conn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)

	cc := tr.NewClientConn(conn)
	_, err = cc.RoundTrip(req)
	require.Error(t, err)
}

func TestClientRequestLengthLimit(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().ConnectionState()
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)

	body := bytes.NewBufferString("request body")
	req, err := http.NewRequest(http.MethodPost, "http://quic-go.net", body)
	require.NoError(t, err)
	req.ContentLength = 7

	var buf bytes.Buffer
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(
		bytes.NewReader(encodeResponse(t, http.StatusTeapot)).Read,
	).AnyTimes()
	str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
	str.EXPECT().Close().Do(func() error { close(done); return nil })
	conn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)

	cc := (&Transport{}).NewClientConn(conn)
	_, err = cc.RoundTrip(req)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	hfs := decodeHeader(t, &buf)
	require.Equal(t, []string{http.MethodPost}, hfs[":method"])
	require.Contains(t, buf.String(), "request")
	require.NotContains(t, buf.String(), "request body")
	// the entire body should have been read (and discarded)
	require.Zero(t, body.Len())
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
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)

	done := make(chan struct{})
	conn.EXPECT().OpenUniStream().DoAndReturn(func() (quic.SendStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()

	b := quicvarint.Append(nil, streamTypeControlStream)
	b = (&settingsFrame{ExtendedConnect: enabled}).Append(b)
	r := bytes.NewReader(b)
	allowSettings := make(chan struct{})

	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
		<-allowSettings
		if r.Len() == 0 {
			<-done
		}
		return r.Read(b)
	}).AnyTimes()
	conn.EXPECT().AcceptUniStream(gomock.Any()).Return(controlStr, nil)
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	})

	if enabled {
		requestStr := mockquic.NewMockStream(mockCtrl)
		requestStr.EXPECT().Write(gomock.Any()).Return(0, assert.AnError)
		requestStr.EXPECT().StreamID().AnyTimes()
		requestStr.EXPECT().Context().Return(context.Background()).AnyTimes()
		conn.EXPECT().OpenStreamSync(gomock.Any()).Return(requestStr, nil)
	}

	cc := (&Transport{}).NewClientConn(conn)
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
	close(allowSettings)

	select {
	case <-cc.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for settings")
	}
	settings := cc.Settings()
	require.Equal(t, enabled, settings.EnableExtendedConnect)

	select {
	case err := <-errChan:
		if enabled {
			require.ErrorIs(t, err, assert.AnError)
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
	mockCtrl := gomock.NewController(t)

	var rspBuf bytes.Buffer
	rstr := NewMockDatagramStream(mockCtrl)
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

	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)
	conn.EXPECT().ConnectionState().MaxTimes(1)

	req, err := http.NewRequest(http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().Close()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(rspBytes).Read).AnyTimes()
	if tooMany {
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))
		str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeExcessiveLoad))
	}
	conn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)

	cc := (&Transport{}).NewClientConn(conn)
	rsp, err := cc.RoundTrip(req)
	if tooMany {
		require.EqualError(t, err, "http3: too many 1xx informational responses")
		return
	}
	require.NoError(t, err)
	require.Equal(t, []string{"foo", "bar"}, rsp.Header["Link"])
	require.Equal(t, terminalStatus, rsp.StatusCode)

	// request headers
	hfs := decodeHeader(t, &buf)
	require.Equal(t, hfs[":method"], []string{http.MethodGet})
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
	mockCtrl := gomock.NewController(t)

	var rspBuf bytes.Buffer
	rstr := NewMockDatagramStream(mockCtrl)
	rstr.EXPECT().Write(gomock.Any()).Do(rspBuf.Write).AnyTimes()
	rw := newResponseWriter(newStream(rstr, nil, func(r io.Reader, u uint64) error { return nil }), nil, false, nil)
	rw.WriteHeader(http.StatusOK)
	if responseAddContentEncoding {
		rw.header.Add("Content-Encoding", "gzip")
	}
	rw.Write(data)
	rw.Flush()

	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)
	conn.EXPECT().ConnectionState().MaxTimes(1)

	req, err := http.NewRequest(http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str.EXPECT().Close()
	str.EXPECT().Read(gomock.Any()).DoAndReturn(bytes.NewReader(rspBuf.Bytes()).Read).AnyTimes()
	conn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)

	cc := (&Transport{DisableCompression: transportDisableCompression}).NewClientConn(conn)
	rsp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	body, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	require.Equal(t, expectedRsp, body)

	// request headers
	hfs := decodeHeader(t, &buf)
	if transportDisableCompression {
		require.NotContains(t, hfs, "accept-encoding")
	} else {
		require.Equal(t, hfs["accept-encoding"], []string{"gzip"})
	}
}

func TestClientRequestCancellationBeforeHandshakeCompletion(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().HandshakeComplete().Return(make(chan struct{})).AnyTimes()
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)

	cc := (&Transport{}).NewClientConn(conn)
	errChan := make(chan error)
	go func() {
		_, err := cc.RoundTrip(req)
		errChan <- err
	}()
	select {
	case <-errChan:
		t.Fatalf("RoundTrip not have returned: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
		t.Fatal("timeout")
	}
}

func TestClientRequestCancellation(t *testing.T) {
	t.Run("before receiving response", func(t *testing.T) {
		testClientRequestCancellation(t, false)
	})
	t.Run("after receiving response", func(t *testing.T) {
		testClientRequestCancellation(t, true)
	})
}

func testClientRequestCancellation(t *testing.T, receiveResponse bool) {
	mockCtrl := gomock.NewController(t)
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	conn.EXPECT().Context().Return(context.Background()).AnyTimes()
	done := make(chan struct{})
	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, assert.AnError
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)

	var buf bytes.Buffer
	str := mockquic.NewMockStream(mockCtrl)
	str.EXPECT().Context().Return(context.Background()).AnyTimes()
	str.EXPECT().StreamID().AnyTimes()
	str.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	// the order doesn't matter, but we should close the done channel after the last of the two calls
	gomock.InOrder(
		str.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled)),
		str.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled)).Do(func(quic.StreamErrorCode) {
			close(done)
		}),
	)
	// repeated cancellations are fine, the QUIC layer will ignore them
	str.EXPECT().CancelWrite(gomock.Any()).AnyTimes()
	str.EXPECT().CancelRead(gomock.Any()).AnyTimes()
	str.EXPECT().Close()
	if receiveResponse {
		str.EXPECT().Read(gomock.Any()).DoAndReturn(
			bytes.NewReader(encodeResponse(t, http.StatusTeapot)).Read,
		).AnyTimes()
		conn.EXPECT().ConnectionState()
	} else {
		str.EXPECT().Read(gomock.Any()).DoAndReturn(func(b []byte) (int, error) {
			<-done
			return 0, errors.New("done")
		}).AnyTimes()
	}
	conn.EXPECT().OpenStreamSync(gomock.Any()).Return(str, nil)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://quic-go.net", nil)
	require.NoError(t, err)

	cc := (&Transport{}).NewClientConn(conn)

	if receiveResponse {
		r, err := cc.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusTeapot, r.StatusCode)
		cancel()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("stream should have been reset")
		}
		return
	}

	errChan := make(chan error)
	go func() {
		_, err := cc.RoundTrip(req)
		errChan <- err
	}()
	select {
	case <-errChan:
		t.Fatalf("RoundTrip not have returned: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
		t.Fatal("timeout")
	}
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

	const id = quic.ConnectionTracingID(1234)
	ctx := context.WithValue(context.Background(), quic.ConnectionTracingKey, id)

	mockCtrl := gomock.NewController(t)
	str := mockquic.NewMockStream(mockCtrl)
	if streamReadErr == nil {
		str.EXPECT().Read(gomock.Any()).DoAndReturn(
			bytes.NewReader(quicvarint.Append(nil, 0x41)).Read,
		).AnyTimes()
	} else {
		str.EXPECT().Read(gomock.Any()).Return(0, streamReadErr).AnyTimes()
	}

	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	conn.EXPECT().HandshakeComplete().Return(closedChan()).AnyTimes()
	conn.EXPECT().Context().Return(ctx).AnyTimes()

	done := make(chan struct{})
	if bidirectional {
		conn.EXPECT().AcceptStream(gomock.Any()).Return(str, nil)
		conn.EXPECT().AcceptStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.Stream, error) {
			<-done
			return nil, errors.New("done")
		}).MaxTimes(1)
		if !doHijack {
			conn.EXPECT().CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), gomock.Any()).AnyTimes()
		}
	} else {
		conn.EXPECT().AcceptUniStream(gomock.Any()).Return(str, nil)
	}

	conn.EXPECT().AcceptUniStream(gomock.Any()).DoAndReturn(func(context.Context) (quic.ReceiveStream, error) {
		<-done
		return nil, errors.New("done")
	}).MaxTimes(1)
	controlStr := mockquic.NewMockStream(mockCtrl)
	controlStr.EXPECT().Write(gomock.Any()).MaxTimes(1)
	conn.EXPECT().OpenUniStream().Return(controlStr, nil).MaxTimes(1)

	_ = tr.NewClientConn(conn)

	select {
	case hijackCall := <-hijackChan:
		assert.Equal(t, id, hijackCall.connTracingID)
		if streamReadErr == nil {
			if bidirectional {
				assert.Equal(t, FrameType(0x41), hijackCall.ft)
			} else {
				assert.Equal(t, StreamType(0x41), hijackCall.st)
			}
			assert.NoError(t, hijackCall.e)
		} else {
			assert.ErrorIs(t, hijackCall.e, streamReadErr)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
