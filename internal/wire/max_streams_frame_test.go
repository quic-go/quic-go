package wire

import (
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_STREAMS frame", func() {
	Context("parsing", func() {
		It("accepts a frame for a bidirectional stream", func() {
			data := encodeVarInt(0xdecaf)
			f, l, err := parseMaxStreamsFrame(data, bidiMaxStreamsFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeBidi))
			Expect(f.MaxStreamNum).To(BeEquivalentTo(0xdecaf))
			Expect(l).To(Equal(len(data)))
		})

		It("accepts a frame for a bidirectional stream", func() {
			data := encodeVarInt(0xdecaf)
			f, l, err := parseMaxStreamsFrame(data, uniMaxStreamsFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeUni))
			Expect(f.MaxStreamNum).To(BeEquivalentTo(0xdecaf))
			Expect(l).To(Equal(len(data)))
		})

		It("errors on EOFs", func() {
			const typ = 0x1d
			data := encodeVarInt(0xdeadbeefcafe13)
			_, l, err := parseMaxStreamsFrame(data, typ, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			for i := range data {
				_, _, err := parseMaxStreamsFrame(data[:i], typ, protocol.Version1)
				Expect(err).To(MatchError(io.EOF))
			}
		})

		for _, t := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
			streamType := t

			It("accepts a frame containing the maximum stream count", func() {
				f := &MaxStreamsFrame{
					Type:         streamType,
					MaxStreamNum: protocol.MaxStreamCount,
				}
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				typ, l, err := quicvarint.Parse(b)
				Expect(err).ToNot(HaveOccurred())
				b = b[l:]
				frame, _, err := parseMaxStreamsFrame(b, typ, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(f))
			})

			It("errors when receiving a too large stream count", func() {
				f := &MaxStreamsFrame{
					Type:         streamType,
					MaxStreamNum: protocol.MaxStreamCount + 1,
				}
				b, err := f.Append(nil, protocol.Version1)
				Expect(err).ToNot(HaveOccurred())
				typ, l, err := quicvarint.Parse(b)
				Expect(err).ToNot(HaveOccurred())
				b = b[l:]
				_, _, err = parseMaxStreamsFrame(b, typ, protocol.Version1)
				Expect(err).To(MatchError(fmt.Sprintf("%d exceeds the maximum stream count", protocol.MaxStreamCount+1)))
			})
		}
	})

	Context("writing", func() {
		It("for a bidirectional stream", func() {
			f := &MaxStreamsFrame{
				Type:         protocol.StreamTypeBidi,
				MaxStreamNum: 0xdeadbeef,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{bidiMaxStreamsFrameType}
			expected = append(expected, encodeVarInt(0xdeadbeef)...)
			Expect(b).To(Equal(expected))
		})

		It("for a unidirectional stream", func() {
			f := &MaxStreamsFrame{
				Type:         protocol.StreamTypeUni,
				MaxStreamNum: 0xdecafbad,
			}
			b, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{uniMaxStreamsFrameType}
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct length", func() {
			frame := MaxStreamsFrame{MaxStreamNum: 0x1337}
			Expect(frame.Length(protocol.Version1)).To(BeEquivalentTo(1 + quicvarint.Len(0x1337)))
		})
	})
})
