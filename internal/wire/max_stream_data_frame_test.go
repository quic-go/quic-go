package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_STREAM_DATA frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x5,
				0xde, 0xad, 0xbe, 0xef, // stream id
				0xde, 0xca, 0xfb, 0xad, 0x11, 0x22, 0x33, 0x44, // byte offset
			})
			frame, err := ParseMaxStreamDataFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad11223344)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x5,
				0xef, 0xbe, 0xad, 0xde, // stream id
				0x44, 0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, // byte offset
			}
			_, err := ParseMaxStreamDataFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseMaxStreamDataFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("has proper min length", func() {
			f := &MaxStreamDataFrame{
				StreamID:   0x1337,
				ByteOffset: 0xdeadbeef,
			}
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(13)))
		})

		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			f := &MaxStreamDataFrame{
				StreamID:   0xdecafbad,
				ByteOffset: 0xdeadbeefcafe1337,
			}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x5,
				0xde, 0xca, 0xfb, 0xad, // stream id
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // byte offset
			}))
		})
	})
})
