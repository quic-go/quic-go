package quic

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("public reset", func() {
	Context("writing", func() {
		It("writes public reset packets", func() {
			Expect(writePublicReset(0xdeadbeef, 0x8badf00d, 0xdecafbad)).To(Equal([]byte{
				0x0a,
				0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
				'P', 'R', 'S', 'T',
				0x02, 0x00, 0x00, 0x00,
				'R', 'N', 'O', 'N',
				0x08, 0x00, 0x00, 0x00,
				'R', 'S', 'E', 'Q',
				0x10, 0x00, 0x00, 0x00,
				0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x0, 0x0,
				0x0d, 0xf0, 0xad, 0x8b, 0x0, 0x0, 0x0, 0x0,
			}))
		})
	})

	Context("parsing", func() {
		var b *bytes.Buffer

		BeforeEach(func() {
			b = &bytes.Buffer{}
		})

		It("parses a public reset", func() {
			packet := writePublicReset(0xdeadbeef, 0x8badf00d, 0xdecafbad)
			pr, err := parsePublicReset(bytes.NewReader(packet[9:])) // 1 byte Public Flag, 8 bytes connection ID
			Expect(err).ToNot(HaveOccurred())
			Expect(pr.nonce).To(Equal(uint64(0xdecafbad)))
			Expect(pr.rejectedPacketNumber).To(Equal(protocol.PacketNumber(0x8badf00d)))
		})

		It("rejects packets that it can't parse", func() {
			_, err := parsePublicReset(bytes.NewReader([]byte{}))
			Expect(err).To(MatchError(io.EOF))
		})

		It("rejects packets with the wrong tag", func() {
			handshake.HandshakeMessage{Tag: handshake.TagREJ, Data: nil}.Write(b)
			_, err := parsePublicReset(bytes.NewReader(b.Bytes()))
			Expect(err).To(MatchError("wrong public reset tag"))
		})

		It("rejects packets missing the nonce", func() {
			data := map[handshake.Tag][]byte{
				handshake.TagRSEQ: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
			}
			handshake.HandshakeMessage{Tag: handshake.TagPRST, Data: data}.Write(b)
			_, err := parsePublicReset(bytes.NewReader(b.Bytes()))
			Expect(err).To(MatchError("RNON missing"))
		})

		It("rejects packets with a wrong length nonce", func() {
			data := map[handshake.Tag][]byte{
				handshake.TagRSEQ: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
				handshake.TagRNON: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13},
			}
			handshake.HandshakeMessage{Tag: handshake.TagPRST, Data: data}.Write(b)
			_, err := parsePublicReset(bytes.NewReader(b.Bytes()))
			Expect(err).To(MatchError("invalid RNON tag"))
		})

		It("rejects packets missing the rejected packet number", func() {
			data := map[handshake.Tag][]byte{
				handshake.TagRNON: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
			}
			handshake.HandshakeMessage{Tag: handshake.TagPRST, Data: data}.Write(b)
			_, err := parsePublicReset(bytes.NewReader(b.Bytes()))
			Expect(err).To(MatchError("RSEQ missing"))
		})

		It("rejects packets with a wrong length rejected packet number", func() {
			data := map[handshake.Tag][]byte{
				handshake.TagRSEQ: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13},
				handshake.TagRNON: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37},
			}
			handshake.HandshakeMessage{Tag: handshake.TagPRST, Data: data}.Write(b)
			_, err := parsePublicReset(bytes.NewReader(b.Bytes()))
			Expect(err).To(MatchError("invalid RSEQ tag"))
		})
	})
})
