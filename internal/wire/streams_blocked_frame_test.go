package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
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
			_, err := parseStreamsBlockedFrame(bytes.NewReader(data), protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				_, err := parseStreamsBlockedFrame(bytes.NewReader(data[:i]), protocol.Version1)
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
				b, err := f.Append(nil, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				frame, err := parseStreamsBlockedFrame(bytes.NewReader(b), protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(f))
			})

			It("errors when receiving a too large stream count", func() {
				f := &StreamsBlockedFrame{
					Type:        streamType,
					StreamLimit: protocol.MaxStreamCount + 1,
				}
				b, err := f.Append(nil, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				_, err = parseStreamsBlockedFrame(bytes.NewReader(b), protocol.VersionWhatever)
				Expect(err).To(MatchError(fmt.Sprintf("%d exceeds the maximum stream count", protocol.MaxStreamCount+1)))
			})
		}
	})

	Context("writing", func() {
		It("writes a frame for bidirectional streams", func() {
			f := StreamsBlockedFrame{
				Type:        protocol.StreamTypeBidi,
				StreamLimit: 0xdeadbeefcafe,
			}
			b, err := f.Append(nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x16}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame for unidirectional streams", func() {
			f := StreamsBlockedFrame{
				Type:        protocol.StreamTypeUni,
				StreamLimit: 0xdeadbeefcafe,
			}
			b, err := f.Append(nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x17}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := StreamsBlockedFrame{StreamLimit: 0x123456}
			Expect(frame.Length(0)).To(Equal(protocol.ByteCount(1) + quicvarint.Len(0x123456)))
		})
	})
})
