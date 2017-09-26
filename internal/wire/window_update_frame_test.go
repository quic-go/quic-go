package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("WindowUpdateFrame", func() {
	Context("when parsing", func() {
		Context("in little endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x4,
					0xef, 0xbe, 0xad, 0xde, // stream id
					0x44, 0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, // byte offset
				})
				frame, err := ParseWindowUpdateFrame(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad11223344)))
				Expect(b.Len()).To(BeZero())
			})
		})

		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x4,
					0xde, 0xad, 0xbe, 0xef, // stream id
					0xde, 0xca, 0xfb, 0xad, 0x11, 0x22, 0x33, 0x44, // byte offset
				})
				frame, err := ParseWindowUpdateFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0xdecafbad11223344)))
				Expect(b.Len()).To(BeZero())
			})
		})

		It("errors on EOFs", func() {
			data := []byte{0x4,
				0xef, 0xbe, 0xad, 0xde, // stream id
				0x44, 0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, // byte offset
			}
			_, err := ParseWindowUpdateFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseWindowUpdateFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("has proper min length", func() {
			f := &WindowUpdateFrame{
				StreamID:   0x1337,
				ByteOffset: 0xdeadbeef,
			}
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(13)))
		})

		Context("in little endian", func() {
			It("writes a sample frame", func() {
				b := &bytes.Buffer{}
				f := &WindowUpdateFrame{
					StreamID:   0xdecafbad,
					ByteOffset: 0xdeadbeefcafe1337,
				}
				err := f.Write(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x4,
					0xad, 0xfb, 0xca, 0xde, // stream id
					0x37, 0x13, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde, // byte offset
				}))
			})
		})

		Context("in big endian", func() {
			It("writes a sample frame", func() {
				b := &bytes.Buffer{}
				f := &WindowUpdateFrame{
					StreamID:   0xdecafbad,
					ByteOffset: 0xdeadbeefcafe1337,
				}
				err := f.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x4,
					0xde, 0xca, 0xfb, 0xad, // stream id
					0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37, // byte offset
				}))
			})
		})
	})
})
