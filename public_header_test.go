package quic

import (
	"bytes"
	"encoding/binary"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Public Header", func() {
	Context("when parsing", func() {
		It("accepts a sample client header", func() {
			b := bytes.NewReader([]byte{0x0d, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 0x51, 0x30, 0x33, 0x30, 0x01})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.VersionFlag).To(BeTrue())
			Expect(publicHeader.ResetFlag).To(BeFalse())
			Expect(publicHeader.ConnectionID).To(Equal(uint64(0x4cfa9f9b668619f6)))
			Expect(publicHeader.QuicVersion).To(Equal(binary.BigEndian.Uint32([]byte("Q030"))))
			Expect(publicHeader.PacketNumber).To(Equal(uint64(1)))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts 4-byte connection IDs", func() {
			b := bytes.NewReader([]byte{0x08, 0x9b, 0x9f, 0xfa, 0x4c, 0x01})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.VersionFlag).To(BeFalse())
			Expect(publicHeader.ConnectionID).To(Equal(uint64(0x4cfa9f9b)))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts 1-byte connection IDs", func() {
			b := bytes.NewReader([]byte{0x04, 0x4c, 0x01})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.VersionFlag).To(BeFalse())
			Expect(publicHeader.ConnectionID).To(Equal(uint64(0x4c)))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts 0-byte connection ID", func() {
			b := bytes.NewReader([]byte{0x00, 0x01})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.VersionFlag).To(BeFalse())
			Expect(b.Len()).To(BeZero())
		})

		It("accepts 2-byte packet numbers", func() {
			b := bytes.NewReader([]byte{0x10, 0xde, 0xca})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.PacketNumber).To(Equal(uint64(0xcade)))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts 4-byte packet numbers", func() {
			b := bytes.NewReader([]byte{0x20, 0xad, 0xfb, 0xca, 0xde})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.PacketNumber).To(Equal(uint64(0xdecafbad)))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts 6-byte packet numbers", func() {
			b := bytes.NewReader([]byte{0x30, 0x23, 0x42, 0xad, 0xfb, 0xca, 0xde})
			publicHeader, err := ParsePublicHeader(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(publicHeader.PacketNumber).To(Equal(uint64(0xdecafbad4223)))
			Expect(b.Len()).To(BeZero())
		})
	})

	Context("when writing", func() {
		It("writes a sample header", func() {
			b := &bytes.Buffer{}
			WritePublicHeader(b, &PublicHeader{
				ConnectionID: 0x4cfa9f9b668619f6,
				PacketNumber: 2,
			})
			Expect(b.Bytes()).To(Equal([]byte{0x2c, 0xf6, 0x19, 0x86, 0x66, 0x9b, 0x9f, 0xfa, 0x4c, 2, 0, 0, 0}))
		})
	})
})
