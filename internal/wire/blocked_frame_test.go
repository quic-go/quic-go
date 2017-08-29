package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("BlockedFrame", func() {
	Context("when parsing", func() {
		Context("in little endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x5, 0xef, 0xbe, 0xad, 0xde})
				frame, err := ParseBlockedFrame(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			})
		})

		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x5, 0xde, 0xad, 0xbe, 0xef})
				frame, err := ParseBlockedFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.StreamID).To(Equal(protocol.StreamID(0xdeadbeef)))
			})
		})

		It("errors on EOFs", func() {
			data := []byte{0x5, 0xef, 0xbe, 0xad, 0xde}
			_, err := ParseBlockedFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseBlockedFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		Context("in little endian", func() {
			It("writes a sample frame", func() {
				b := &bytes.Buffer{}
				frame := BlockedFrame{StreamID: 0x1337}
				frame.Write(b, versionLittleEndian)
				Expect(b.Bytes()).To(Equal([]byte{0x5, 0x37, 0x13, 0x0, 0x0}))
			})
		})

		Context("in big endian", func() {
			It("writes a sample frame", func() {
				b := &bytes.Buffer{}
				frame := BlockedFrame{StreamID: 0x1337}
				frame.Write(b, versionBigEndian)
				Expect(b.Bytes()).To(Equal([]byte{0x5, 0x0, 0x0, 0x13, 0x37}))
			})
		})

		It("writes a connection-level Blocked", func() {
			b := &bytes.Buffer{}
			frame := BlockedFrame{StreamID: 0}
			frame.Write(b, 0)
			Expect(b.Bytes()).To(Equal([]byte{0x5, 0, 0, 0, 0}))
		})

		It("has the correct min length", func() {
			frame := BlockedFrame{StreamID: 3}
			Expect(frame.MinLength(0)).To(Equal(protocol.ByteCount(5)))
		})
	})
})
