package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("StreamFrame", func() {
	Context("stream frames", func() {
		Context("when parsing", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0xa0, 0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'})
				frame, err := ParseStreamFrame(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.FinBit).To(BeFalse())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
				Expect(frame.Offset).To(BeZero())
				Expect(frame.Data).To(Equal([]byte("foobar")))
			})

			It("accepts frame without datalength", func() {
				b := bytes.NewReader([]byte{0x80, 0x1, 'f', 'o', 'o', 'b', 'a', 'r'})
				frame, err := ParseStreamFrame(b)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.FinBit).To(BeFalse())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(1)))
				Expect(frame.Offset).To(BeZero())
				Expect(frame.Data).To(Equal([]byte("foobar")))
			})
		})

		Context("when writing", func() {
			It("writes sample frame", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 1,
					Data:     []byte("foobar"),
				}).Write(b)
				Expect(b.Bytes()).To(Equal([]byte{0xa3, 0x1, 0, 0, 0, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'}))
			})

			It("writes offsets", func() {
				b := &bytes.Buffer{}
				(&StreamFrame{
					StreamID: 1,
					Offset:   16,
					Data:     []byte("foobar"),
				}).Write(b)
				Expect(b.Bytes()).To(Equal([]byte{0xbf, 0x1, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'}))
			})

			It("has proper max length", func() {
				b := &bytes.Buffer{}
				f := &StreamFrame{
					StreamID: 1,
					Data:     []byte("f"),
					Offset:   1,
				}
				f.Write(b)
				Expect(f.MaxLength()).To(Equal(b.Len()))
			})
		})
	})
})
