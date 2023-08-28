package http3

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go"
	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

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
			str           Stream
			qstr          *mockquic.MockStream
			buf           *bytes.Buffer
			errorCbCalled bool
		)

		errorCb := func() { errorCbCalled = true }

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			errorCbCalled = false
			qstr = mockquic.NewMockStream(mockCtrl)
			qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
			qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
			str = newStream(qstr, errorCb)
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

		It("skips HEADERS frames", func() {
			b := getDataFrame([]byte("foo"))
			b = (&headersFrame{Length: 10}).Append(b)
			b = append(b, make([]byte, 10)...)
			b = append(b, getDataFrame([]byte("bar"))...)
			buf.Write(b)
			r := make([]byte, 6)
			n, err := io.ReadFull(str, r)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(r).To(Equal([]byte("foobar")))
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
			str := newStream(qstr, nil)
			str.Write([]byte("foo"))
			str.Write([]byte("foobar"))

			f, err := parseNextFrame(buf, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(&dataFrame{Length: 3}))
			b := make([]byte, 3)
			_, err = io.ReadFull(buf, b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte("foo")))

			f, err = parseNextFrame(buf, nil)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(&dataFrame{Length: 6}))
			b = make([]byte, 6)
			_, err = io.ReadFull(buf, b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b).To(Equal([]byte("foobar")))
		})
	})
})

var _ = Describe("length-limited streams", func() {
	var (
		str  *stream
		qstr *mockquic.MockStream
		buf  *bytes.Buffer
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		qstr = mockquic.NewMockStream(mockCtrl)
		qstr.EXPECT().Write(gomock.Any()).DoAndReturn(buf.Write).AnyTimes()
		qstr.EXPECT().Read(gomock.Any()).DoAndReturn(buf.Read).AnyTimes()
		str = newStream(qstr, func() { Fail("didn't expect error callback to be called") })
	})

	It("reads all frames", func() {
		s := newLengthLimitedStream(str, 6)
		buf.Write(getDataFrame([]byte("foo")))
		buf.Write(getDataFrame([]byte("bar")))
		data, err := io.ReadAll(s)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("foobar")))
	})

	It("errors if more data than the maximum length is sent, in the middle of a frame", func() {
		s := newLengthLimitedStream(str, 4)
		buf.Write(getDataFrame([]byte("foo")))
		buf.Write(getDataFrame([]byte("bar")))
		qstr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
		qstr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
		data, err := io.ReadAll(s)
		Expect(err).To(MatchError(errTooMuchData))
		Expect(data).To(Equal([]byte("foob")))
		// check that repeated calls to Read also return the right error
		n, err := s.Read([]byte{0})
		Expect(n).To(BeZero())
		Expect(err).To(MatchError(errTooMuchData))
	})

	It("errors if more data than the maximum length is sent, as an additional frame", func() {
		s := newLengthLimitedStream(str, 3)
		buf.Write(getDataFrame([]byte("foo")))
		buf.Write(getDataFrame([]byte("bar")))
		qstr.EXPECT().CancelRead(quic.StreamErrorCode(ErrCodeMessageError))
		qstr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeMessageError))
		data, err := io.ReadAll(s)
		Expect(err).To(MatchError(errTooMuchData))
		Expect(data).To(Equal([]byte("foo")))
	})
})
