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
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, 0x1337, protocol.VersionWhatever)
	Expect(err).ToNot(HaveOccurred())
	res, err := nullAEAD.Open(dst, src, packetNumber, associatedData)
	return res, m.encLevelOpen, err
}
func (m *mockAEAD) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel) {
	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, 0x1337, protocol.VersionWhatever)
	Expect(err).ToNot(HaveOccurred())
	return nullAEAD.Seal(dst, src, packetNumber, associatedData), protocol.EncryptionUnspecified
}

var _ quicAEAD = &mockAEAD{}

var _ = Describe("Packet unpacker", func() {
	var (
		unpacker *packetUnpacker
		hdr      *wire.Header
		hdrBin   []byte
		data     []byte
		buf      *bytes.Buffer
	)

	BeforeEach(func() {
		hdr = &wire.Header{
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

	It("errors if the packet doesn't contain any payload", func() {
		setData(nil)
		_, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("saves the encryption level", func() {
		unpacker.version = versionGQUICFrames
		f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, versionGQUICFrames)
		Expect(err).ToNot(HaveOccurred())
		setData(buf.Bytes())
		unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
		packet, err := unpacker.Unpack(hdrBin, hdr, data)
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionSecure))
	})

	Context("for gQUIC frames", func() {
		BeforeEach(func() {
			unpacker.version = versionGQUICFrames
		})

		It("handles PADDING frames", func() {
			setData([]byte{0, 0, 0}) // 3 bytes PADDING
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(BeEmpty())
		})

		It("handles PADDING between two other frames", func() {
			f := &wire.PingFrame{}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			_, err = buf.Write(bytes.Repeat([]byte{0}, 10)) // 10 bytes PADDING
			Expect(err).ToNot(HaveOccurred())
			err = f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(HaveLen(2))
		})

		It("unpacks RST_STREAM frames", func() {
			f := &wire.RstStreamFrame{
				StreamID:   0xdeadbeef,
				ByteOffset: 0xdecafbad11223344,
				ErrorCode:  0x1337,
			}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks CONNECTION_CLOSE frames", func() {
			f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks GOAWAY frames", func() {
			f := &wire.GoawayFrame{
				ErrorCode:      1,
				LastGoodStream: 2,
				ReasonPhrase:   "foo",
			}
			err := f.Write(buf, 0)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks a stream-level WINDOW_UPDATE frame", func() {
			f := &wire.MaxStreamDataFrame{
				StreamID:   0xdeadbeef,
				ByteOffset: 0xcafe000000001337,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks a connection-level WINDOW_UPDATE frame", func() {
			f := &wire.MaxDataFrame{
				ByteOffset: 0xcafe000000001337,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks connection-level BLOCKED frames", func() {
			f := &wire.BlockedFrame{}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks stream-level BLOCKED frames", func() {
			f := &wire.StreamBlockedFrame{StreamID: 0xdeadbeef}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks STOP_WAITING frames", func() {
			setData([]byte{0x06, 0x03})
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{
				&wire.StopWaitingFrame{LeastUnacked: 7},
			}))
		})

		It("unpacks PING frames", func() {
			setData([]byte{0x07})
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{
				&wire.PingFrame{},
			}))
		})

		It("errors on invalid type", func() {
			setData([]byte{0xf})
			_, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0xf"))
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

		It("unpacks ACK frames", func() {
			f := &wire.AckFrame{
				LargestAcked: 0x13,
				LowestAcked:  1,
			}
			err := f.Write(buf, versionGQUICFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(HaveLen(1))
			readFrame := packet.frames[0].(*wire.AckFrame)
			Expect(readFrame).ToNot(BeNil())
			Expect(readFrame.LargestAcked).To(Equal(protocol.PacketNumber(0x13)))
		})

		Context("unpacking STREAM frames", func() {
			It("unpacks unencrypted STREAM frames on the crypto stream", func() {
				unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionUnencrypted
				f := &wire.StreamFrame{
					StreamID: versionGQUICFrames.CryptoStreamID(),
					Data:     []byte("foobar"),
				}
				err := f.Write(buf, versionGQUICFrames)
				Expect(err).ToNot(HaveOccurred())
				setData(buf.Bytes())
				packet, err := unpacker.Unpack(hdrBin, hdr, data)
				Expect(err).ToNot(HaveOccurred())
				Expect(packet.frames).To(Equal([]wire.Frame{f}))
			})

			It("unpacks encrypted STREAM frames on the crypto stream", func() {
				unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
				f := &wire.StreamFrame{
					StreamID: versionGQUICFrames.CryptoStreamID(),
					Data:     []byte("foobar"),
				}
				err := f.Write(buf, versionGQUICFrames)
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
				err := f.Write(buf, versionGQUICFrames)
				Expect(err).ToNot(HaveOccurred())
				setData(buf.Bytes())
				_, err = unpacker.Unpack(hdrBin, hdr, data)
				Expect(err).To(MatchError(qerr.Error(qerr.UnencryptedStreamData, "received unencrypted stream data on stream 3")))
			})
		})
	})

	Context("for IETF draft frames", func() {
		BeforeEach(func() {
			unpacker.version = versionIETFFrames
		})

		It("unpacks RST_STREAM frames", func() {
			f := &wire.RstStreamFrame{
				StreamID:   0xdeadbeef,
				ByteOffset: 0xdecafbad1234,
				ErrorCode:  0x1337,
			}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks CONNECTION_CLOSE frames", func() {
			f := &wire.ConnectionCloseFrame{ReasonPhrase: "foo"}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks MAX_DATA frames", func() {
			f := &wire.MaxDataFrame{
				ByteOffset: 0xcafe,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks MAX_STREAM_DATA frames", func() {
			f := &wire.MaxStreamDataFrame{
				StreamID:   0xdeadbeef,
				ByteOffset: 0xdecafbad,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks MAX_STREAM_ID frames", func() {
			f := &wire.MaxStreamIDFrame{StreamID: 0x1337}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks connection-level BLOCKED frames", func() {
			f := &wire.BlockedFrame{Offset: 0x1234}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks stream-level BLOCKED frames", func() {
			f := &wire.StreamBlockedFrame{
				StreamID: 0xdeadbeef,
				Offset:   0xdead,
			}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks STREAM_ID_BLOCKED frames", func() {
			f := &wire.StreamIDBlockedFrame{StreamID: 0x1234567}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks STOP_SENDING frames", func() {
			f := &wire.StopSendingFrame{StreamID: 0x42}
			buf := &bytes.Buffer{}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(Equal([]wire.Frame{f}))
		})

		It("unpacks ACK frames", func() {
			f := &wire.AckFrame{
				LargestAcked: 0x13,
				LowestAcked:  1,
			}
			err := f.Write(buf, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			setData(buf.Bytes())
			packet, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).ToNot(HaveOccurred())
			Expect(packet.frames).To(HaveLen(1))
			readFrame := packet.frames[0].(*wire.AckFrame)
			Expect(readFrame).ToNot(BeNil())
			Expect(readFrame.LargestAcked).To(Equal(protocol.PacketNumber(0x13)))
		})

		It("errors on invalid type", func() {
			setData([]byte{0xf})
			_, err := unpacker.Unpack(hdrBin, hdr, data)
			Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0xf"))
		})

		It("errors on invalid frames", func() {
			for b, e := range map[byte]qerr.ErrorCode{
				0x01: qerr.InvalidRstStreamData,
				0x02: qerr.InvalidConnectionCloseData,
				0x04: qerr.InvalidWindowUpdateData,
				0x05: qerr.InvalidWindowUpdateData,
				0x06: qerr.InvalidFrameData,
				0x08: qerr.InvalidBlockedData,
				0x09: qerr.InvalidBlockedData,
				0x0a: qerr.InvalidFrameData,
				0x0c: qerr.InvalidFrameData,
				0x0e: qerr.InvalidAckData,
				0x10: qerr.InvalidStreamData,
			} {
				setData([]byte{b})
				_, err := unpacker.Unpack(hdrBin, hdr, data)
				Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(e))
			}
		})

		Context("unpacking STREAM frames", func() {
			It("unpacks unencrypted STREAM frames on the crypto stream", func() {
				unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionUnencrypted
				f := &wire.StreamFrame{
					StreamID: versionIETFFrames.CryptoStreamID(),
					Data:     []byte("foobar"),
				}
				err := f.Write(buf, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				setData(buf.Bytes())
				packet, err := unpacker.Unpack(hdrBin, hdr, data)
				Expect(err).ToNot(HaveOccurred())
				Expect(packet.frames).To(Equal([]wire.Frame{f}))
			})

			It("unpacks encrypted STREAM frames on the crypto stream", func() {
				unpacker.aead.(*mockAEAD).encLevelOpen = protocol.EncryptionSecure
				f := &wire.StreamFrame{
					StreamID: versionIETFFrames.CryptoStreamID(),
					Data:     []byte("foobar"),
				}
				err := f.Write(buf, versionIETFFrames)
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
				err := f.Write(buf, versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				setData(buf.Bytes())
				_, err = unpacker.Unpack(hdrBin, hdr, data)
				Expect(err).To(MatchError(qerr.Error(qerr.UnencryptedStreamData, "received unencrypted stream data on stream 3")))
			})
		})
	})
})
