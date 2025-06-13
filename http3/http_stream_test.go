package http3

import (
	"bytes"
	"context"
	"github.com/Noooste/fhttp"
	"io"
	"math"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"

	"github.com/Noooste/uquic-go"
	mockquic "github.com/Noooste/uquic-go/internal/mocks/quic"
	"github.com/Noooste/uquic-go/internal/protocol"

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

	str := newStream(
		qstr,
		newConnection(
			context.Background(),
			mockquic.NewMockEarlyConnection(mockCtrl),
			false,
			protocol.PerspectiveClient,
			nil,
			0,
		),
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
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	var errCode quic.ApplicationErrorCode
	conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(
		func(e quic.ApplicationErrorCode, msg string) error {
			errCode = e
			return nil
		},
	).AnyTimes()

	str := newStream(
		qstr,
		newConnection(context.Background(), conn, false, protocol.PerspectiveClient, nil, 0),
		func(r io.Reader, u uint64) error { return nil },
	)

	b := (&settingsFrame{}).Append(nil)
	buf.Write(b)
	_, err := str.Read([]byte{0})
	require.ErrorContains(t, err, "peer sent an unexpected frame")
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameUnexpected), errCode)
}

func TestStreamWrite(t *testing.T) {
	var buf bytes.Buffer
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
	str := newStream(qstr, nil, func(r io.Reader, u uint64) error { return nil })
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
	conn := mockquic.NewMockEarlyConnection(mockCtrl)
	str := newRequestStream(
		newStream(
			qstr,
			newConnection(context.Background(), conn, false, protocol.PerspectiveClient, nil, 0),
			func(r io.Reader, u uint64) error { return nil },
		),
		requestWriter,
		make(chan struct{}),
		qpack.NewDecoder(func(qpack.HeaderField) {}),
		true,
		math.MaxUint64,
		&http.Response{},
		&httptrace.ClientTrace{},
	)

	_, err := str.Read(make([]byte, 100))
	require.EqualError(t, err, "http3: invalid use of RequestStream.Read: need to call ReadResponse first")

	req := httptest.NewRequest(http.MethodGet, "https://quic-go.net", nil)
	qstr.EXPECT().Write(gomock.Any()).AnyTimes()
	require.NoError(t, str.SendRequestHeader(req))
	// duplicate calls are not allowed
	require.EqualError(t, str.SendRequestHeader(req), "http3: invalid duplicate use of SendRequestHeader")

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
