package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet packer", func() {
	var (
		packer *packetPacker
	)

	BeforeEach(func() {
		aead := &crypto.NullAEAD{}
		packer = &packetPacker{aead: aead}
	})

	It("returns nil when no packet is queued", func() {
		p, err := packer.PackPacket()
		Expect(p).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})

	It("packs single packets", func() {
		f := &frames.AckFrame{}
		packer.AddFrame(f)
		p, err := packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		b := &bytes.Buffer{}
		f.Write(b, 1, 6)
		Expect(p.payload).To(Equal(b.Bytes()))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("packs multiple frames into single packet", func() {
		f1 := &frames.AckFrame{LargestObserved: 1}
		f2 := &frames.AckFrame{LargestObserved: 2}
		packer.AddFrame(f1)
		packer.AddFrame(f2)
		p, err := packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		b := &bytes.Buffer{}
		f1.Write(b, 2, 6)
		f2.Write(b, 2, 6)
		Expect(p.payload).To(Equal(b.Bytes()))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("packs many normal frames into 2 packets", func() {
		f := &frames.AckFrame{LargestObserved: 1}
		b := &bytes.Buffer{}
		f.Write(b, 3, 6)
		for i := 0; i <= (protocol.MaxFrameSize-1)/b.Len()+1; i++ {
			packer.AddFrame(f)
		}
		p, err := packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(len(p.payload) % b.Len()).To(BeZero())
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
		p, err = packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(p.payload).To(Equal(b.Bytes()))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("splits stream frames", func() {
		f := &frames.StreamFrame{
			Data:   bytes.Repeat([]byte{'f'}, protocol.MaxFrameSize),
			Offset: 1,
		}
		b := &bytes.Buffer{}
		f.Write(b, 4, 6)
		packer.AddFrame(f)
		p, err := packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(len(p.raw)).To(Equal(protocol.MaxPacketSize))
		Expect(err).ToNot(HaveOccurred())
		p, err = packer.PackPacket()
		Expect(p).ToNot(BeNil())
		Expect(err).ToNot(HaveOccurred())
	})
})
