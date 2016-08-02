package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GoawayFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{
				0x03,
				0x01, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0x03, 0x00,
				'f', 'o', 'o',
			})
			frame, err := ParseGoawayFrame(b)
			Expect(frame).To(Equal(&GoawayFrame{
				ErrorCode:      1,
				LastGoodStream: 2,
				ReasonPhrase:   "foo",
			}))
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(0))
		})

		It("rejects long reason phrases", func() {
			b := bytes.NewReader([]byte{
				0x03,
				0x01, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0xff, 0xff,
			})
			_, err := ParseGoawayFrame(b)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidGoawayData, "reason phrase too long")))
		})

		It("errors on EOFs", func() {
			data := []byte{0x03,
				0x01, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0x03, 0x00,
				'f', 'o', 'o',
			}
			_, err := ParseGoawayFrame(bytes.NewReader(data))
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseGoawayFrame(bytes.NewReader(data[0:i]))
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := GoawayFrame{
				ErrorCode:      1,
				LastGoodStream: 2,
				ReasonPhrase:   "foo",
			}
			frame.Write(b, 0)
			Expect(b.Bytes()).To(Equal([]byte{
				0x03,
				0x01, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x00, 0x00,
				0x03, 0x00,
				'f', 'o', 'o',
			}))
		})

		It("has the correct min length", func() {
			frame := GoawayFrame{
				ReasonPhrase: "foo",
			}
			Expect(frame.MinLength(0)).To(Equal(protocol.ByteCount(14)))
		})
	})
})
