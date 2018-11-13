package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frame parsing", func() {
	var buf *bytes.Buffer

	BeforeEach(func() {
		buf = &bytes.Buffer{}
	})

	It("returns nil if there's nothing more to read", func() {
		f, err := ParseNextFrame(bytes.NewReader(nil), protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).To(BeNil())
	})

	It("skips PADDING frames", func() {
		buf.Write([]byte{0}) // PADDING frame
		(&PingFrame{}).Write(buf, versionIETFFrames)
		f, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).To(Equal(&PingFrame{}))
	})

	It("handles PADDING at the end", func() {
		r := bytes.NewReader([]byte{0, 0, 0})
		f, err := ParseNextFrame(r, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(f).To(BeNil())
		Expect(r.Len()).To(BeZero())
	})

	It("unpacks ACK frames", func() {
		f := &AckFrame{AckRanges: []AckRange{{Smallest: 1, Largest: 0x13}}}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(BeAssignableToTypeOf(f))
		Expect(frame.(*AckFrame).LargestAcked()).To(Equal(protocol.PacketNumber(0x13)))
	})

	It("unpacks RESET_STREAM frames", func() {
		f := &ResetStreamFrame{
			StreamID:   0xdeadbeef,
			ByteOffset: 0xdecafbad1234,
			ErrorCode:  0x1337,
		}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks STOP_SENDING frames", func() {
		f := &StopSendingFrame{StreamID: 0x42}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks CRYPTO frames", func() {
		f := &CryptoFrame{
			Offset: 0x1337,
			Data:   []byte("lorem ipsum"),
		}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(Equal(f))
	})

	It("unpacks NEW_TOKEN frames", func() {
		f := &NewTokenFrame{Token: []byte("foobar")}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(Equal(f))
	})

	It("unpacks STREAM frames", func() {
		f := &StreamFrame{
			StreamID: 0x42,
			Offset:   0x1337,
			FinBit:   true,
			Data:     []byte("foobar"),
		}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(Equal(f))
	})

	It("unpacks MAX_DATA frames", func() {
		f := &MaxDataFrame{
			ByteOffset: 0xcafe,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks MAX_STREAM_DATA frames", func() {
		f := &MaxStreamDataFrame{
			StreamID:   0xdeadbeef,
			ByteOffset: 0xdecafbad,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks MAX_STREAMS frames", func() {
		f := &MaxStreamsFrame{
			Type:       protocol.StreamTypeBidi,
			MaxStreams: 0x1337,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks DATA_BLOCKED frames", func() {
		f := &DataBlockedFrame{DataLimit: 0x1234}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks STREAM_DATA_BLOCKED frames", func() {
		f := &StreamDataBlockedFrame{
			StreamID:  0xdeadbeef,
			DataLimit: 0xdead,
		}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks STREAMS_BLOCKED frames", func() {
		f := &StreamsBlockedFrame{
			Type:        protocol.StreamTypeBidi,
			StreamLimit: 0x1234567,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks NEW_CONNECTION_ID frames", func() {
		f := &NewConnectionIDFrame{
			SequenceNumber:      0x1337,
			ConnectionID:        protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
			StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		}
		buf := &bytes.Buffer{}
		Expect(f.Write(buf, versionIETFFrames)).To(Succeed())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks PATH_CHALLENGE frames", func() {
		f := &PathChallengeFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(BeAssignableToTypeOf(f))
		Expect(frame.(*PathChallengeFrame).Data).To(Equal([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	})

	It("unpacks PATH_RESPONSE frames", func() {
		f := &PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).ToNot(BeNil())
		Expect(frame).To(BeAssignableToTypeOf(f))
		Expect(frame.(*PathResponseFrame).Data).To(Equal([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	})

	It("unpacks CONNECTION_CLOSE frames", func() {
		f := &ConnectionCloseFrame{
			IsApplicationError: true,
			ReasonPhrase:       "foobar",
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("errors on invalid type", func() {
		_, err := ParseNextFrame(bytes.NewReader([]byte{0x42}), versionIETFFrames)
		Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0x42"))
	})

	It("errors on invalid frames", func() {
		f := &MaxStreamDataFrame{
			StreamID:   0x1337,
			ByteOffset: 0xdeadbeef,
		}
		b := &bytes.Buffer{}
		f.Write(b, versionIETFFrames)
		_, err := ParseNextFrame(bytes.NewReader(b.Bytes()[:b.Len()-2]), versionIETFFrames)
		Expect(err).To(HaveOccurred())
		Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(qerr.InvalidFrameData))
	})
})
