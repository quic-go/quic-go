package http3

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"

	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"

	"github.com/quic-go/qpack"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

func getDataFrame(data []byte) []byte {
	b := (&dataFrame{Length: uint64(len(data))}).Append(nil)
	return append(b, data...)
}

var _ = Describe("Stream", func() {
	Context("reading", func() {
		var (
			str           *stream
			qstr          *mockquic.MockStream
			buf           *bytes.Buffer
			errorCbCalled bool
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			errorCbCalled = false
			qstr = mockquic.NewMockStream(mockCtrl)
			qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
			qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			conn := mockquic.NewMockEarlyConnection(mockCtrl)
			conn.EXPECT().CloseWithError(gomock.Any(), gomock.Any()).Do(func(qerr.ApplicationErrorCode, string) error {
				errorCbCalled = true
				return nil
			}).AnyTimes()
			str = newStream(qstr, newConnection(context.Background(), conn, false, protocol.PerspectiveClient, nil, 0), nil, func(r io.Reader, u uint64) error { return nil })
		})

		It("reads DATA frames in a single run", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 6)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b).To(Equal([]byte("foobar")))
		})

		It("reads DATA frames in multiple runs", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 3)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b).To(Equal([]byte("foo")))
			n, err = str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b).To(Equal([]byte("bar")))
		})

		It("reads DATA frames into too large buffers", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 10)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b[:n]).To(Equal([]byte("foobar")))
		})

		It("reads DATA frames into too large buffers, in multiple runs", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 4)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte("foob")))
			n, err = str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b[:n]).To(Equal([]byte("ar")))
		})

		It("reads multiple DATA frames", func() {
			buf.Write(getDataFrame([]byte("foo")))
			buf.Write(getDataFrame([]byte("bar")))
			b := make([]byte, 6)
			n, err := str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b[:n]).To(Equal([]byte("foo")))
			n, err = str.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b[:n]).To(Equal([]byte("bar")))
		})

		It("errors when it can't parse the frame", func() {
			buf.Write([]byte("invalid"))
			_, err := str.Read([]byte{0})
			Expect(err).To(HaveOccurred())
		})

		It("errors on unexpected frames, and calls the error callback", func() {
			b := (&settingsFrame{}).Append(nil)
			buf.Write(b)
			_, err := str.Read([]byte{0})
			Expect(err).To(MatchError("peer sent an unexpected frame: *http3.settingsFrame"))
			Expect(errorCbCalled).To(BeTrue())
		})
	})

	Context("writing", func() {
		It("writes data frames", func() {
			buf := &bytes.Buffer{}
			qstr := mockquic.NewMockStream(mockCtrl)
			qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
			str := newStream(qstr, nil, nil, func(r io.Reader, u uint64) error { return nil })
			str.Write([]byte("foo"))
			str.Write([]byte("foobar"))

			fp := frameParser{r: buf}
			f, err := fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(&dataFrame{Length: 3}))
			b := make([]byte, 3)
			_, err = io.ReadFull(buf, b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte("foo")))

			fp = frameParser{r: buf}
			f, err = fp.ParseNext()
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(&dataFrame{Length: 6}))
			b = make([]byte, 6)
			_, err = io.ReadFull(buf, b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte("foobar")))
		})
	})
})

var _ = Describe("Request Stream", func() {
	var str *requestStream
	var qstr *mockquic.MockStream

	BeforeEach(func() {
		qstr = mockquic.NewMockStream(mockCtrl)
		requestWriter := newRequestWriter()
		conn := mockquic.NewMockEarlyConnection(mockCtrl)
		str = newRequestStream(
			newStream(qstr, newConnection(context.Background(), conn, false, protocol.PerspectiveClient, nil, 0), nil, func(r io.Reader, u uint64) error { return nil }),
			requestWriter,
			make(chan struct{}),
			qpack.NewDecoder(func(qpack.HeaderField) {}),
			true,
			math.MaxUint64,
			&http.Response{},
			&httptrace.ClientTrace{},
		)
	})

	It("refuses to read before having read the response", func() {
		_, err := str.Read(make([]byte, 100))
		Expect(err).To(MatchError("http3: invalid use of RequestStream.Read: need to call ReadResponse first"))
	})

	It("prevents duplicate calls to SendRequestHeader", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic-go.net", nil)
		Expect(err).ToNot(HaveOccurred())
		qstr.EXPECT().Write(gomock.Any()).AnyTimes()
		Expect(str.SendRequestHeader(req)).To(Succeed())
		Expect(str.SendRequestHeader(req)).To(MatchError("http3: invalid duplicate use of SendRequestHeader"))
	})

	It("reads after the response", func() {
		req, err := http.NewRequest(http.MethodGet, "https://quic-go.net", nil)
		Expect(err).ToNot(HaveOccurred())
		qstr.EXPECT().Write(gomock.Any()).AnyTimes()
		Expect(str.SendRequestHeader(req)).To(Succeed())

		buf := bytes.NewBuffer(encodeResponse(200))
		buf.Write((&dataFrame{Length: 6}).Append(nil))
		buf.Write([]byte("foobar"))
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		rsp, err := str.ReadResponse()
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		b := make([]byte, 10)
		n, err := str.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(6))
		Expect(b[:n]).To(Equal([]byte("foobar")))
	})
})
