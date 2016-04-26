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
		Expect(len(p.frames)).To(Equal(1))
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
		Expect(len(p.frames)).To(Equal(2))
		Expect(p.raw).To(ContainSubstring(string(b.Bytes())))
	})

	It("packs many normal frames into 2 packets", func() {
		f := &frames.AckFrame{LargestObserved: 1}
		b := &bytes.Buffer{}
		f.Write(b, 3, 6)
		maxFramesPerPacket := protocol.MaxFrameSize / b.Len()
		counter := 0
		for i := 0; i < maxFramesPerPacket+1; i++ {
			packer.AddFrame(f)
			counter++
		}
		payloadFrames, err := packer.composeNextPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(payloadFrames)).To(Equal(maxFramesPerPacket))
		payloadFrames, err = packer.composeNextPacket()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(payloadFrames)).To(Equal(counter - maxFramesPerPacket))
	})

	Context("Stream Frame handling", func() {
		It("does not splits a stream frame with maximum size", func() {
			maxStreamFrameDataLen := protocol.MaxFrameSize - (1 + 4 + 8 + 2)
			f := &frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, maxStreamFrameDataLen),
				Offset: 1,
			}
			packer.AddFrame(f)
			payloadFrames, err := packer.composeNextPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
			payloadFrames, err = packer.composeNextPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(0))
		})

		It("packs 2 stream frames that are too big for one packet correctly", func() {
			maxStreamFrameDataLen := protocol.MaxFrameSize - (1 + 4 + 8 + 2)
			f1 := &frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, maxStreamFrameDataLen+100),
				Offset: 1,
			}
			f2 := &frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, maxStreamFrameDataLen+100),
				Offset: 1,
			}
			packer.AddFrame(f1)
			packer.AddFrame(f2)
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(p.raw)).To(Equal(protocol.MaxPacketSize))
			p, err = packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(p.raw)).To(Equal(protocol.MaxPacketSize))
			p, err = packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
		})

		It("packs a packet that has the maximum packet size when given a large enough stream frame", func() {
			f := &frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, protocol.MaxFrameSize-(1+4+8+2)),
				Offset: 1,
			}
			packer.AddFrame(f)
			p, err := packer.PackPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(p).ToNot(BeNil())
			Expect(len(p.raw)).To(Equal(protocol.MaxPacketSize))
		})

		It("splits a stream frame larger than the maximum size", func() {
			f := &frames.StreamFrame{
				Data:   bytes.Repeat([]byte{'f'}, protocol.MaxFrameSize-(1+4+8+2)+1),
				Offset: 1,
			}
			packer.AddFrame(f)
			payloadFrames, err := packer.composeNextPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
			payloadFrames, err = packer.composeNextPacket()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(payloadFrames)).To(Equal(1))
		})
	})
})
