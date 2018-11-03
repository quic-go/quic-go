package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
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

	It("unpacks RST_STREAM frames", func() {
		f := &RstStreamFrame{
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

	It("unpacks CONNECTION_CLOSE frames containing QUIC error codes", func() {
		f := &ConnectionCloseFrame{ReasonPhrase: "foo"}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks CONNECTION_CLOSE frames containing application error codes", func() {
		f := &ConnectionCloseFrame{
			IsApplicationError: true,
			ReasonPhrase:       "foo",
		}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
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

	It("unpacks MAX_STREAM_ID frames", func() {
		f := &MaxStreamIDFrame{StreamID: 0x1337}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks connection-level BLOCKED frames", func() {
		f := &BlockedFrame{Offset: 0x1234}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks stream-level BLOCKED frames", func() {
		f := &StreamBlockedFrame{
			StreamID: 0xdeadbeef,
			Offset:   0xdead,
		}
		buf := &bytes.Buffer{}
		err := f.Write(buf, versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		frame, err := ParseNextFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
		Expect(err).ToNot(HaveOccurred())
		Expect(frame).To(Equal(f))
	})

	It("unpacks STREAM_ID_BLOCKED frames", func() {
		f := &StreamIDBlockedFrame{StreamID: 0x1234567}
		buf := &bytes.Buffer{}
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

	It("errors on invalid type", func() {
		_, err := ParseNextFrame(bytes.NewReader([]byte{0x42}), versionIETFFrames)
		Expect(err).To(MatchError("InvalidFrameData: unknown type byte 0x42"))
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
			0x0e: qerr.InvalidFrameData,
			0x0f: qerr.InvalidFrameData,
			0x10: qerr.InvalidStreamData,
			0x1a: qerr.InvalidAckData,
			0x1b: qerr.InvalidAckData,
		} {
			_, err := ParseNextFrame(bytes.NewReader([]byte{b}), versionIETFFrames)
			Expect(err).To(HaveOccurred())
			Expect(err.(*qerr.QuicError).ErrorCode).To(Equal(e))
		}
	})
})
