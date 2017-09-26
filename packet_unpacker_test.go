package quic

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type mockAEAD struct {
	encLevelOpen protocol.EncryptionLevel
}

func (m *mockAEAD) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	nullAEAD := crypto.NewNullAEAD(protocol.PerspectiveClient, protocol.VersionWhatever)
	res, err := nullAEAD.Open(dst, src, packetNumber, associatedData)
	return res, m.encLevelOpen, err
}
func (m *mockAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel) {
	nullAEAD := crypto.NewNullAEAD(protocol.PerspectiveServer, protocol.VersionWhatever)
	return nullAEAD.Seal(dst, src, packetNumber, associatedData), protocol.EncryptionUnspecified
}

var _ quicAEAD = &mockAEAD{}

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *wire.PublicHeader
		hdrBin   []byte
		data     []byte
		buf      *bytes.Buffer
	)

	BeforeEach(func() {
		hdr = &wire.PublicHeader{
			PacketNumber:    10,
			PacketNumberLen: 1,
		}
		hdrBin = []byte{0x04, 0x4c, 0x01}
		unpacker = &packetUnpacker{aead: &mockAEAD{}}
		data = nil
		buf = &bytes.Buffer{}
	})

	setData := func(p []byte) {
		data, _ = unpacker.aead.(*mockAEAD).Seal(nil, p, 0, hdrBin)
	}

	It("does not read read a private flag for QUIC Version >= 34", func() {
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{f}))
	})

	It("saves the encryption level", func() {
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionSecure))
	})

	It("unpacks ACK frames", func() {
		unpacker.version = protocol.VersionWhatever
		f := &wire.AckFrame{
			LargestAcked: 0x13,
			LowestAcked:  1,
		}
		err := f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(1))
		readFrame := packet.frames[0].(*wire.AckFrame)
		Expect(readFrame).ToNot(BeNil())
		Expect(readFrame.LargestAcked).To(Equal(protocol.PacketNumber(0x13)))
	})

	It("errors on CONGESTION_FEEDBACK frames", func() {
		setData([]byte{0x20})
		_, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).To(MatchError("unimplemented: CONGESTION_FEEDBACK"))
	})

	It("handles PADDING frames", func() {
		setData([]byte{0, 0, 0}) // 3 bytes PADDING
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(BeEmpty())
	})

	It("handles PADDING between two other frames", func() {
		f := &wire.PingFrame{}
		err := f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		_, err = buf.Write(bytes.Repeat([]byte{0}, 10)) // 10 bytes PADDING
		Expect(err).ToNot(HaveOccurred())
		err = f.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(HaveLen(2))
	})

	It("unpacks RST_STREAM frames", func() {
		setData([]byte{0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x44, 0x33, 0x22, 0x11, 0xAD, 0xFB, 0xCA, 0xDE, 0x34, 0x12, 0x37, 0x13})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.RstStreamFrame{
				StreamID:   0xDEADBEEF,
				ByteOffset: 0xDECAFBAD11223344,
				ErrorCode:  0x13371234,
			},
		}))
	})

	It("unpacks CONNECTION_CLOSE frames", func() {
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, 0)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{f}))
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
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.GoawayFrame{
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
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.WindowUpdateFrame{
				StreamID:   0xDEADBEEF,
				ByteOffset: 0xCAFE000000001337,
			},
		}))
	})

	It("accepts BLOCKED frames", func() {
		setData([]byte{0x05, 0xEF, 0xBE, 0xAD, 0xDE})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.BlockedFrame{StreamID: 0xDEADBEEF},
		}))
	})

	It("unpacks STOP_WAITING frames", func() {
		setData([]byte{0x06, 0x03})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.StopWaitingFrame{LeastUnacked: 7},
		}))
	})

	It("accepts PING frames", func() {
		setData([]byte{0x07})
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{
			&wire.PingFrame{},
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

	Context("unpacking STREAM frames", func() {
		It("unpacks unencrypted STREAM frames on stream 1", func() {
			unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionUnencrypted
			f := &wire.StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks encrypted STREAM frames on stream 1", func() {
			unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
			f := &wire.StreamFrame{
				StreamID: 1,
				Data:     []byte("foobar"),
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("does not unpack unencrypted STREAM frames on higher streams", func() {
			unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionUnencrypted
			f := &wire.StreamFrame{
				StreamID: 3,
				Data:     []byte("foobar"),
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			_, err = unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).To(MatchError(qerr.Error(qerr.UnencryptedStreamData, "received unencrypted stream data on stream 3")))
		})
	})
})
