package http3

import (
	"bytes"
	"io"

	mockquic "github.com/quic-go/quic-go/internal/mocks/quic"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream", func() {
	Context("reading", func() {
		var (
			str           Stream
			qstr          *mockquic.MockStream
			buf           *bytes.Buffer
			errorCbCalled bool
		)

		errorCb := func() { errorCbCalled = true }
		getDataFrame := func(data []byte) []byte {
			b := (&dataFrame{Length: uint64(len(data))}).Append(nil)
			return append(b, data...)
		}

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
