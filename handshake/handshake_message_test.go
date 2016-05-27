package handshake

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Handshake Message", func() {
	Context("when parsing", func() {
		It("parses sample CHLO message", func() {
			tag, msg, err := ParseHandshakeMessage(bytes.NewReader(sampleCHLO))
			Expect(err).ToNot(HaveOccurred())
			Expect(tag).To(Equal(TagCHLO))
			Expect(msg).To(Equal(sampleCHLOMap))
		})

		It("rejects large numbers of pairs", func() {
			r := bytes.NewReader([]byte("CHLO\xff\xff\xff\xff"))
			_, _, err := ParseHandshakeMessage(r)
			Expect(err).To(MatchError(qerr.CryptoTooManyEntries))
		})

		It("rejects too long values", func() {
			r := bytes.NewReader([]byte{
				'C', 'H', 'L', 'O',
				1, 0, 0, 0,
				0, 0, 0, 0,
				0xff, 0xff, 0xff, 0xff,
			})
			_, _, err := ParseHandshakeMessage(r)
			Expect(err).To(MatchError(qerr.Error(qerr.CryptoInvalidValueLength, "value too long")))
		})
	})

	Context("when writing", func() {
		It("writes sample message", func() {
			b := &bytes.Buffer{}
			WriteHandshakeMessage(b, TagCHLO, sampleCHLOMap)
			Expect(b.Bytes()).To(Equal(sampleCHLO))
		})
	})
})
