package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("STREAMS_BLOCKED frame", func() {
	Context("parsing", func() {
		It("accepts a frame for bidirectional streams", func() {
			expected := []byte{0x16}
			expected = append(expected, encodeVarInt(0x1337)...)
			b := bytes.NewReader(expected)
			f, err := parseStreamsBlockedFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeBidi))
			Expect(f.StreamLimit).To(BeEquivalentTo(0x1337))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts a frame for unidirectional streams", func() {
			expected := []byte{0x17}
			expected = append(expected, encodeVarInt(0x7331)...)
			b := bytes.NewReader(expected)
			f, err := parseStreamsBlockedFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeUni))
			Expect(f.StreamLimit).To(BeEquivalentTo(0x7331))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x16}
			data = append(data, encodeVarInt(0x12345678)...)
			_, err := parseStreamsBlockedFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				_, err := parseStreamsBlockedFrame(bytes.NewReader(data[:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})

		for _, t := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
			streamType := t

			It("accepts a frame containing the maximum stream count", func() {
				f := &StreamsBlockedFrame{
					Type:        streamType,
					StreamLimit: protocol.MaxStreamCount,
				}
				b := &bytes.Buffer{}
				Expect(f.Write(b, protocol.VersionWhatever)).To(Succeed())
				frame, err := parseStreamsBlockedFrame(bytes.NewReader(b.Bytes()), protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(f))
			})

			It("errors when receiving a too large stream count", func() {
				f := &StreamsBlockedFrame{
					Type:        streamType,
					StreamLimit: protocol.MaxStreamCount + 1,
				}
				b := &bytes.Buffer{}
				Expect(f.Write(b, protocol.VersionWhatever)).To(Succeed())
				_, err := parseStreamsBlockedFrame(bytes.NewReader(b.Bytes()), protocol.VersionWhatever)
				Expect(err).To(MatchError(fmt.Sprintf("%d exceeds the maximum stream count", protocol.MaxStreamCount+1)))
			})
		}
	})

	Context("writing", func() {
		It("writes a frame for bidirectional streams", func() {
			b := &bytes.Buffer{}
			f := StreamsBlockedFrame{
				Type:        protocol.StreamTypeBidi,
				StreamLimit: 0xdeadbeefcafe,
			}
			Expect(f.Write(b, protocol.VersionWhatever)).To(Succeed())
			expected := []byte{0x16}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("writes a frame for unidirectional streams", func() {
			b := &bytes.Buffer{}
			f := StreamsBlockedFrame{
				Type:        protocol.StreamTypeUni,
				StreamLimit: 0xdeadbeefcafe,
			}
			Expect(f.Write(b, protocol.VersionWhatever)).To(Succeed())
			expected := []byte{0x17}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := StreamsBlockedFrame{StreamLimit: 0x123456}
			Expect(frame.Length(0)).To(Equal(protocol.ByteCount(1) + utils.VarIntLen(0x123456)))
		})
	})
})
