package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RstStreamFrame", func() {
	Context("when parsing", func() {
		Context("in little endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x1,
					0xef, 0xbe, 0xad, 0xde, // stream id
					0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // byte offset
					0x34, 0x12, 0x37, 0x13, // error code
				})
				frame, err := ParseRstStreamFrame(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0x1122334455667788)))
				Expect(frame.ErrorCode).To(Equal(uint32(0x13371234)))
			})
		})

		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x1,
					0xde, 0xad, 0xbe, 0xef, // stream id
					0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // byte offset
					0x34, 0x12, 0x37, 0x13, // error code
				})
				frame, err := ParseRstStreamFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
				Expect(frame.ByteOffset).To(Equal(protocol.ByteCount(0x8877665544332211)))
				Expect(frame.ErrorCode).To(Equal(uint32(0x34123713)))
			})
		})

		It("errors on EOFs", func() {
			data := []byte{0x1,
				0xef, 0xbe, 0xad, 0xde, 0x44, // stream id
				0x33, 0x22, 0x11, 0xad, 0xfb, 0xca, 0xde, 0x34, // byte offset
				0x12, 0x37, 0x13, // error code
			}
			_, err := ParseRstStreamFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseRstStreamFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		Context("in little endian", func() {
			It("writes a sample RstStreamFrame", func() {
				frame := RstStreamFrame{
					StreamID:   0x1337,
					ByteOffset: 0x11223344decafbad,
					ErrorCode:  0xdeadbeef,
				}
				b := &bytes.Buffer{}
				err := frame.Write(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x01,
					0x37, 0x13, 0x0, 0x0, // stream id
					0xad, 0xfb, 0xca, 0xde, 0x44, 0x33, 0x22, 0x11, // byte offset
					0xef, 0xbe, 0xad, 0xde, // error code
				}))
			})
		})

		Context("in big endian", func() {
			It("writes a sample RstStreamFrame", func() {
				frame := RstStreamFrame{
					StreamID:   0x1337,
					ByteOffset: 0x11223344decafbad,
					ErrorCode:  0xdeadbeef,
				}
				b := &bytes.Buffer{}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Bytes()).To(Equal([]byte{0x01,
					0x0, 0x0, 0x13, 0x37, // stream id
					0x11, 0x22, 0x33, 0x44, 0xde, 0xca, 0xfb, 0xad, // byte offset
					0xde, 0xad, 0xbe, 0xef, // error code
				}))
			})
		})

		It("has the correct min length", func() {
			rst := RstStreamFrame{
				StreamID:   0x1337,
				ByteOffset: 0x1000,
				ErrorCode:  0xde,
			}
			Expect(rst.MinLength(0)).To(Equal(protocol.ByteCount(17)))
		})
	})
})
