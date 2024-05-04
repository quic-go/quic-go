package wire

import (
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
			data := encodeVarInt(0x1337)
			f, l, err := parseStreamsBlockedFrame(data, bidiStreamBlockedFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeBidi))
			Expect(f.StreamLimit).To(BeEquivalentTo(0x1337))
			Expect(l).To(Equal(len(data)))
		})

		It("accepts a frame for unidirectional streams", func() {
			data := encodeVarInt(0x7331)
			f, l, err := parseStreamsBlockedFrame(data, uniStreamBlockedFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeUni))
			Expect(f.StreamLimit).To(BeEquivalentTo(0x7331))
			Expect(l).To(Equal(len(data)))
		})

		It("errors on EOFs", func() {
			data := encodeVarInt(0x12345678)
			_, l, err := parseStreamsBlockedFrame(data, bidiStreamBlockedFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			for i := range data {
				_, _, err := parseStreamsBlockedFrame(data[:i], bidiStreamBlockedFrameType, protocol.Version1)
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
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				typ, l, err := quicvarint.Parse(b)
				Expect(err).ToNot(HaveOccurred())
				b = b[l:]
				frame, l, err := parseStreamsBlockedFrame(b, typ, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(f))
				Expect(l).To(Equal(len(b)))
			})

			It("errors when receiving a too large stream count", func() {
				f := &StreamsBlockedFrame{
					Type:        streamType,
					StreamLimit: protocol.MaxStreamCount + 1,
				}
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				typ, l, err := quicvarint.Parse(b)
				Expect(err).ToNot(HaveOccurred())
				b = b[l:]
				_, _, err = parseStreamsBlockedFrame(b, typ, protocol.Version1)
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
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{bidiStreamBlockedFrameType}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b).To(Equal(expected))
		})

		It("writes a frame for unidirectional streams", func() {
			f := StreamsBlockedFrame{
				Type:        protocol.StreamTypeUni,
				StreamLimit: 0xdeadbeefcafe,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{uniStreamBlockedFrameType}
			expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := StreamsBlockedFrame{StreamLimit: 0x123456}
			Expect(frame.Length(0)).To(Equal(1 + protocol.ByteCount(quicvarint.Len(0x123456))))
		})
	})
})
