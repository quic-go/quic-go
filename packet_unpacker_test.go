package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *PublicHeader
		hdrBin   []byte
		aead     crypto.AEAD
		r        *bytes.Reader
		buf      *bytes.Buffer
	)

	BeforeEach(func() {
		aead = &crypto.NullAEAD{}
		hdr = &PublicHeader{
			PacketNumber:    1,
			PacketNumberLen: 1,
		}
		hdrBin = []byte{0x04, 0x4c, 0x01}
		unpacker = &packetUnpacker{aead: aead}
		r = nil
		buf = &bytes.Buffer{}
	})

	setReader := func(data []byte) {
		r = bytes.NewReader(aead.Seal(0, hdrBin, append([]byte{0x01}, data...)))
	}

	It("unpacks empty packets", func() {
		setReader(nil)
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.entropyBit).To(BeTrue())
		Expect(packet.frames).To(HaveLen(0))
	})

	It("unpacks stream frames", func() {
		f := &frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("foobar"),
		}
		err := f.Write(buf, 3, 6)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("unpacks ack frames", func() {
		f := &frames.AckFrame{
			LargestObserved: 1,
			DelayTime:       1,
		}
		err := f.Write(buf, 3, 6)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("unpacks ack frames", func() {
		f := &frames.AckFrame{
			LargestObserved: 1,
			DelayTime:       1,
		}
		err := f.Write(buf, 3, 6)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("errors on CONGESTION_FEEDBACK frames", func() {
		setReader([]byte{0x20})
		_, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).To(MatchError("unimplemented: CONGESTION_FEEDBACK"))
	})

	It("handles pad frames", func() {
		setReader([]byte{0, 0, 0})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(0))
	})

	It("unpacks RST_STREAM frames", func() {
		setReader([]byte{0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE, 0x34, 0x12, 0x37, 0x13})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.RstStreamFrame{
				StreamID:   0xDEADBEEF,
				ByteOffset: 0xDECAFBAD11223344,
				ErrorCode:  0x13371234,
			},
		}))
	})

	It("unpacks CONNECTION_CLOSE frames", func() {
		f := &frames.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 6, 6)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("errors on GOAWAY frames", func() {
		setReader([]byte{0x03})
		_, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).To(MatchError("unimplemented: GOAWAY"))
	})

	It("accepts WINDOW_UPDATE frames", func() {
		setReader([]byte{0x04, 0xEF, 0xBE, 0xAD, 0xDE, 0x37, 0x13, 0, 0, 0, 0, 0xFE, 0xCA})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.WindowUpdateFrame{
				StreamID:   0xDEADBEEF,
				ByteOffset: 0xCAFE000000001337,
			},
		}))
	})

	It("accepts BLOCKED frames", func() {
		setReader([]byte{0x05, 0, 0, 0, 0})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(0))
	})

	It("unpacks STOP_WAITING frames", func() {
		setReader([]byte{0x06, 0xA4, 0x03})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.StopWaitingFrame{
				Entropy:           0xA4,
				LeastUnackedDelta: 0x03,
			},
		}))
	})

	It("accepts PING frames", func() {
		setReader([]byte{0x07})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(0))
	})

	It("errors on invalid type", func() {
		setReader([]byte{0x08})
		_, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).To(MatchError("unknown type byte 0x8"))
	})
})
