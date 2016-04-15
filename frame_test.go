package quic

import (
	"bytes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frame", func() {
	Context("stream frames", func() {
		Context("when parsing", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x1, 0x06, 0x00, 'f', 'o', 'o', 'b', 'a', 'r'})
				frame, err := ParseStreamFrame(b, 0xa0)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.FinBit).To(BeFalse())
				Expect(frame.StreamID).To(Equal(uint32(1)))
				Expect(frame.Offset).To(BeZero())
				Expect(frame.Data).To(Equal([]byte("foobar")))
			})

			It("accepts frame without datalength", func() {
				b := bytes.NewReader([]byte{0x1, 'f', 'o', 'o', 'b', 'a', 'r'})
				frame, err := ParseStreamFrame(b, 0x80)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.FinBit).To(BeFalse())
				Expect(frame.StreamID).To(Equal(uint32(1)))
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
		})
	})

	Context("ACK frames", func() {
		Context("when writing", func() {
			It("writes simple frames", func() {
				b := &bytes.Buffer{}
				(&AckFrame{
					Entropy:         2,
					LargestObserved: 1,
				}).Write(b)
				Expect(b.Bytes()).To(Equal([]byte{0x48, 0x02, 0x01, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0}))
			})
		})
	})
})
