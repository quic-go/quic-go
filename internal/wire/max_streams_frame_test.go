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

var _ = Describe("MAX_STREAMS frame", func() {
	Context("parsing", func() {
		It("accepts a frame for a bidirectional stream", func() {
			data := encodeVarInt(0xdecaf)
			b := bytes.NewReader(data)
			f, err := parseMaxStreamsFrame(b, bidiMaxStreamsFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeBidi))
			Expect(f.MaxStreamNum).To(BeEquivalentTo(0xdecaf))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts a frame for a bidirectional stream", func() {
			data := encodeVarInt(0xdecaf)
			b := bytes.NewReader(data)
			f, err := parseMaxStreamsFrame(b, uniMaxStreamsFrameType, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeUni))
			Expect(f.MaxStreamNum).To(BeEquivalentTo(0xdecaf))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			const typ = 0x1d
			data := encodeVarInt(0xdeadbeefcafe13)
			_, err := parseMaxStreamsFrame(bytes.NewReader(data), typ, protocol.Version1)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err = parseMaxStreamsFrame(bytes.NewReader(data[:i]), typ, protocol.Version1)
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
				r := bytes.NewReader(b)
				typ, err := quicvarint.Read(r)
				Expect(err).ToNot(HaveOccurred())
				frame, err := parseMaxStreamsFrame(r, typ, protocol.Version1)
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
				r := bytes.NewReader(b)
				typ, err := quicvarint.Read(r)
				Expect(err).ToNot(HaveOccurred())
				_, err = parseMaxStreamsFrame(r, typ, protocol.Version1)
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
			Expect(frame.Length(protocol.Version1)).To(Equal(1 + quicvarint.Len(0x1337)))
		})
	})
})
