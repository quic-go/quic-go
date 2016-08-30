package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *PublicHeader
		hdrBin   []byte
		aead     crypto.AEAD
		data     []byte
		buf      *bytes.Buffer
	)

	BeforeEach(func() {
		aead = &crypto.NullAEAD{}
		hdr = &PublicHeader{
			PacketNumber:    10,
			PacketNumberLen: 1,
		}
		hdrBin = []byte{0x04, 0x4c, 0x01}
		unpacker = &packetUnpacker{aead: aead}
		data = nil
		buf = &bytes.Buffer{}
	})

	setData := func(p []byte) {
		data = aead.Seal(nil, p, 0, hdrBin)
	}

	It("does not read read a private flag for QUIC Version >= 34", func() {
		f := &frames.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("unpacks stream frames", func() {
		f := &frames.StreamFrame{
			StreamID: 1,
			Data:     []byte("foobar"),
		}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("unpacks ACK frames", func() {
		unpacker.version = protocol.Version34
		f := &frames.AckFrame{
			LargestAcked: 0x13,
			LowestAcked:  1,
		}
		err := f.Write(buf, protocol.Version34)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(1))
		readFrame := packet.frames[0].(*frames.AckFrame)
		Expect(readFrame).ToNot(BeNil())
		Expect(readFrame.LargestAcked).To(Equal(protocol.PacketNumber(0x13)))
	})

	It("errors on CONGESTION_FEEDBACK frames", func() {
		setData([]byte{0x20})
		_, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).To(MatchError("unimplemented: CONGESTION_FEEDBACK"))
	})

	It("handles pad frames", func() {
		setData([]byte{0, 0, 0})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(BeEmpty())
	})

	It("unpacks RST_STREAM frames", func() {
		setData([]byte{0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE, 0x34, 0x12, 0x37, 0x13})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
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
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{f}))
	})

	It("accepts GOAWAY frames", func() {
		setData([]byte{
			0x03,
			0x01, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x00, 0x00,
			0x03, 0x00,
			'f', 'o', 'o',
		})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
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
		setData([]byte{0x04, 0xEF, 0xBE, 0xAD, 0xDE, 0x37, 0x13, 0, 0, 0, 0, 0xFE, 0xCA})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.WindowUpdateFrame{
				StreamID:   0xDEADBEEF,
				ByteOffset: 0xCAFE000000001337,
			},
		}))
	})

	It("accepts BLOCKED frames", func() {
		setData([]byte{0x05, 0xEF, 0xBE, 0xAD, 0xDE})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.BlockedFrame{
				StreamID: 0xDEADBEEF,
			},
		}))
	})

	It("unpacks STOP_WAITING frames", func() {
		setData([]byte{0x06, 0x03})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.StopWaitingFrame{
				LeastUnacked: 7,
			},
		}))
	})

	It("accepts PING frames", func() {
		setData([]byte{0x07})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]frames.Frame{
			&frames.PingFrame{},
		}))
	})

	It("errors on invalid type", func() {
		setData([]byte{0x08})
		_, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0x8"))
	})

	It("errors on invalid frames", func() {
		for b, e := range map[byte]qerr.ErrorCode{
			0x80: qerr.InvalidStreamData,
			0x40: qerr.InvalidAckData,
			0x01: qerr.InvalidRstStreamData,
			0x02: qerr.InvalidConnectionCloseData,
			0x03: qerr.InvalidGoawayData,
			0x04: qerr.InvalidWindowUpdateData,
			0x05: qerr.InvalidBlockedData,
			0x06: qerr.InvalidStopWaitingData,
		} {
			setData([]byte{b})
			_, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(e))
		}
	})
})
