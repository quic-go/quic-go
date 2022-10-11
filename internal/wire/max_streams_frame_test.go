package wire

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("MAX_STREAMS frame", func() {
	Context("parsing", func() {
		It("accepts a frame for a bidirectional stream", func() {
			data := []byte{0x12}
			data = append(data, encodeVarInt(0xdecaf)...)
			b := bytes.NewReader(data)
			f, err := parseMaxStreamsFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeBidi))
			Expect(f.MaxStreamNum).To(BeEquivalentTo(0xdecaf))
			Expect(b.Len()).To(BeZero())
		})

		It("accepts a frame for a bidirectional stream", func() {
			data := []byte{0x13}
			data = append(data, encodeVarInt(0xdecaf)...)
			b := bytes.NewReader(data)
			f, err := parseMaxStreamsFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.Type).To(Equal(protocol.StreamTypeUni))
			Expect(f.MaxStreamNum).To(BeEquivalentTo(0xdecaf))
			Expect(b.Len()).To(BeZero())
		})

		It("errors on EOFs", func() {
			data := []byte{0x1d}
			data = append(data, encodeVarInt(0xdeadbeefcafe13)...)
			_, err := parseMaxStreamsFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseMaxStreamsFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})

		for _, t := range []protocol.StreamType{protocol.StreamTypeUni, protocol.StreamTypeBidi} {
			streamType := t

			It("accepts a frame containing the maximum stream count", func() {
				f := &MaxStreamsFrame{
					Type:         streamType,
					MaxStreamNum: protocol.MaxStreamCount,
				}
				b, err := f.Append(nil, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				frame, err := parseMaxStreamsFrame(bytes.NewReader(b), protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame).To(Equal(f))
			})

			It("errors when receiving a too large stream count", func() {
				f := &MaxStreamsFrame{
					Type:         streamType,
					MaxStreamNum: protocol.MaxStreamCount + 1,
				}
				b, err := f.Append(nil, protocol.VersionWhatever)
				Expect(err).ToNot(HaveOccurred())
				_, err = parseMaxStreamsFrame(bytes.NewReader(b), protocol.VersionWhatever)
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
			b, err := f.Append(nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x12}
			expected = append(expected, encodeVarInt(0xdeadbeef)...)
			Expect(b).To(Equal(expected))
		})

		It("for a unidirectional stream", func() {
			f := &MaxStreamsFrame{
				Type:         protocol.StreamTypeUni,
				MaxStreamNum: 0xdecafbad,
			}
			b, err := f.Append(nil, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			expected := []byte{0x13}
			expected = append(expected, encodeVarInt(0xdecafbad)...)
			Expect(b).To(Equal(expected))
		})

		It("has the correct length", func() {
			frame := MaxStreamsFrame{MaxStreamNum: 0x1337}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(1 + quicvarint.Len(0x1337)))
		})
	})
})
