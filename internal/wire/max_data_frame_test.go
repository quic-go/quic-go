package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_DATA frame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x4,
				0xde, 0xca, 0xfb, 0xad, 0x11, 0x22, 0x33, 0x44, // byte offset
			})
			frame, err := ParseMaxDataFrame(b, versionBigEndian)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad11223344)))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x4,
				0x44, 0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, // byte offset
			}
			_, err := ParseMaxDataFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseMaxDataFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("has proper min length", func() {
			f := &MaxDataFrame{
				ByteOffset: 0xdeadbeef,
			}
			Expect(f.MinLength(versionIETFFrames)).To(Equal(protocol.ByteCount(1 + 8)))
		})

		It("writes a MAX_DATA frame", func() {
			b := &bytes.Buffer{}
			f := &MaxDataFrame{
				ByteOffset: 0xdeadbeefcafe1337,
			}
			err := f.Write(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Bytes()).To(Equal([]byte{0x4,
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // byte offset
			}))
		})
	})
})
