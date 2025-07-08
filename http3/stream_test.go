package http3

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/quic-go/qpack"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func getDataFrame(data []byte) []byte {
	b := (&dataFrame{Length: uint64(len(data))}).Append(nil)
	return append(b, data...)
}

func TestStreamReadDataFrames(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()

	clientConn, _ := newConnPair(t)
	str := newStream(
		qstr,
		newConnection(
			clientConn.Context(),
			clientConn,
			false,
			false, // client
			nil,
			0,
		),
		nil,
		func(r io.Reader, u uint64) error { return nil },
	)

	buf.Write(getDataFrame([]byte("foobar")))
	b := make([]byte, 3)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("foo"), b)
	n, err = str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("bar"), b)

	buf.Write(getDataFrame([]byte("baz")))
	b = make([]byte, 10)
	n, err = str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, []byte("baz"), b[:n])

	buf.Write(getDataFrame([]byte("lorem")))
	buf.Write(getDataFrame([]byte("ipsum")))

	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, "loremipsum", string(data))

	// invalid frame
	buf.Write([]byte("invalid"))
	_, err = str.Read([]byte{0})
	require.Error(t, err)
}

func TestStreamInvalidFrame(t *testing.T) {
	var buf bytes.Buffer
	b := (&settingsFrame{}).Append(nil)
	buf.Write(b)

	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	clientConn, serverConn := newConnPair(t)

	str := newStream(
		qstr,
		newConnection(context.Background(), clientConn, false, false, nil, 0),
		nil,
		func(r io.Reader, u uint64) error { return nil },
	)

	_, err := str.Read([]byte{0})
	require.ErrorContains(t, err, "peer sent an unexpected frame")

	select {
	case <-serverConn.Context().Done():
		var appErr *quic.ApplicationError
		require.ErrorAs(t, context.Cause(serverConn.Context()), &appErr)
		require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameUnexpected), appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestStreamWrite(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str := newStream(qstr, nil, nil, func(r io.Reader, u uint64) error { return nil })
	str.Write([]byte("foo"))
	str.Write([]byte("foobar"))

	fp := frameParser{r: &buf}
	f, err := fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, &dataFrame{Length: 3}, f)
	b := make([]byte, 3)
	_, err = io.ReadFull(&buf, b)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), b)

	fp = frameParser{r: &buf}
	f, err = fp.ParseNext()
	require.NoError(t, err)
	require.Equal(t, &dataFrame{Length: 6}, f)
	b = make([]byte, 6)
	_, err = io.ReadFull(&buf, b)
	require.NoError(t, err)
	require.Equal(t, []byte("foobar"), b)
}

func TestRequestStream(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	requestWriter := newRequestWriter()
	clientConn, _ := newConnPair(t)
	str := newRequestStream(
		newStream(
			qstr,
			newConnection(context.Background(), clientConn, false, false, nil, 0),
			&httptrace.ClientTrace{},
			func(r io.Reader, u uint64) error { return nil },
		),
		requestWriter,
		make(chan struct{}),
		qpack.NewDecoder(func(qpack.HeaderField) {}),
		true,
		math.MaxUint64,
		&http.Response{},
	)

	_, err := str.Read([]byte{0})
	require.EqualError(t, err, "http3: invalid use of RequestStream.Read before ReadResponse")
	_, err = str.Write([]byte{0})
	require.EqualError(t, err, "http3: invalid use of RequestStream.Write before SendRequestHeader")

	// calling ReadResponse before SendRequestHeader is not valid
	_, err = str.ReadResponse()
	require.EqualError(t, err, "http3: invalid duplicate use of RequestStream.ReadResponse before SendRequestHeader")
	// SendRequestHeader can't be used for requests that have a request body
	require.EqualError(t,
		str.SendRequestHeader(
			httptest.NewRequest(http.MethodGet, "https://quic-go.net", strings.NewReader("foobar")),
		),
		"http3: invalid use of RequestStream.SendRequestHeader with a request that has a request body",
	)

	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net", nil)
	qstr.EXPECT().Write(gomock.Any()).AnyTimes()
	require.NoError(t, str.SendRequestHeader(req))
	// duplicate calls are not allowed
	require.EqualError(t, str.SendRequestHeader(req), "http3: invalid duplicate use of RequestStream.SendRequestHeader")

	buf := bytes.NewBuffer(encodeResponse(t, 200))
	buf.Write((&dataFrame{Length: 6}).Append(nil))
	buf.Write([]byte("foobar"))
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	rsp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)

	b := make([]byte, 10)
	n, err := str.Read(b)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte("foobar"), b[:n])
}
