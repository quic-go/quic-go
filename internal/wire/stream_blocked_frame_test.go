package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAM_BLOCKED frame", func() {
	Context("parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x9,
				0xde, 0xad, 0xbe, 0xef, // stream id
			})
			frame, err := ParseStreamBlockedFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x9,
				0xef, 0xbe, 0xad, 0xde, // stream id
			}
			_, err := ParseStreamBlockedFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseStreamBlockedFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("has proper min length", func() {
			f := &StreamBlockedFrame{
				StreamID: 0x1337,
			}
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(5)))
		})

		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			f := &StreamBlockedFrame{
				StreamID: 0xdecafbad,
			}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x9,
				0xde, 0xca, 0xfb, 0xad, // stream id
			}))
		})
	})
})
