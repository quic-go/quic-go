package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *publicHeader
		hdrBin   []byte
		aead     crypto.AEAD
		r        *bytes.Reader
		buf      *bytes.Buffer
	)

	BeforeEach(func() {
		aead = &crypto.NullAEAD{}
		hdr = &publicHeader{
			PacketNumber:    10,
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
		Expect(packet.frames).To(BeEmpty())
	})

	It("unpacks stream frames", func() {
		f := &frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("foobar"),
		}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("unpacks ack frames", func() {
		f := &frames.AckFrame{
			LargestObserved: 0x13,
			Entropy:         0x37,
		}
		err := f.Write(buf, protocol.Version32)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(1))
		readFrame := packet.frames[0].(*frames.AckFrame)
		Expect(readFrame.LargestObserved).To(Equal(protocol.PacketNumber(0x13)))
		Expect(readFrame.Entropy).To(Equal(byte(0x37)))
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
		Expect(packet.frames).To(BeEmpty())
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
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setReader(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("accepts GOAWAY frames", func() {
		setReader([]byte{
			0x03,
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00,
			'f', 'o', 'o',
		})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.GoawayFrame{
				ErrorCode:      1,
				LastGoodStream: 2,
				ReasonPhrase:   "foo",
			},
		}))
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
		setReader([]byte{0x05, 0xEF, 0xBE, 0xAD, 0xDE})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.BlockedFrame{
				StreamID: 0xDEADBEEF,
			},
		}))
	})

	It("unpacks STOP_WAITING frames", func() {
		setReader([]byte{0x06, 0xA4, 0x03})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.StopWaitingFrame{
				Entropy:      0xA4,
				LeastUnacked: 7,
			},
		}))
	})

	It("accepts PING frames", func() {
		setReader([]byte{0x07})
		packet, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.PingFrame{},
		}))
	})

	It("errors on invalid type", func() {
		setReader([]byte{0x08})
		_, err := unpacker.Unpack(hdrBin, hdr, r)
		Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0x8"))
	})
})
