package frames

import (
	"bytes"
	"strings"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConnectionCloseFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0x19, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x4e, 0x6f, 0x20, 0x72, 0x65, 0x63, 0x65, 0x6e, 0x74, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x2e})
			frame, err := ParseConnectionCloseFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ErrorCode).To(Equal(qerr.ErrorCode(0x19)))
			Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame without a reason phrase", func() {
			b := bytes.NewReader([]byte{0x02, 0xAD, 0xFB, 0xCA, 0xDE, 0x00, 0x00})
			frame, err := ParseConnectionCloseFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ErrorCode).To(Equal(qerr.ErrorCode(0xDECAFBAD)))
			Expect(frame.ReasonPhrase).To(BeEmpty())
			Expect(b.Len()).To(Equal(0))
		})

		It("rejects long reason phrases", func() {
			b := bytes.NewReader([]byte{0x02, 0xAD, 0xFB, 0xCA, 0xDE, 0xff, 0xf})
			_, err := ParseConnectionCloseFrame(b)
			Expect(err).To(MatchError(qerr.Error(qerr.InvalidConnectionCloseData, "reason phrase too long")))
		})

		It("errors on EOFs", func() {
			data := []byte{0x40, 0x19, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x4e, 0x6f, 0x20, 0x72, 0x65, 0x63, 0x65, 0x6e, 0x74, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x2e}
			_, err := ParseConnectionCloseFrame(bytes.NewReader(data))
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := ParseConnectionCloseFrame(bytes.NewReader(data[0:i]))
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("when writing", func() {
		It("writes a frame without a ReasonPhrase", func() {
			b := &bytes.Buffer{}
			frame := &ConnectionCloseFrame{
				ErrorCode: 0xDEADBEEF,
			}
			err := frame.Write(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(1 + 2 + 4))
			Expect(b.Bytes()).To(Equal([]byte{0x02, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00}))
		})

		It("writes a frame with a ReasonPhrase", func() {
			b := &bytes.Buffer{}
			frame := &ConnectionCloseFrame{
				ErrorCode:    0xDEADBEEF,
				ReasonPhrase: "foobar",
			}
			err := frame.Write(b, 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(1 + 2 + 4 + len(frame.ReasonPhrase)))
			Expect(b.Bytes()[:5]).To(Equal([]byte{0x02, 0xEF, 0xBE, 0xAD, 0xDE}))
			Expect(b.Bytes()[5:7]).To(Equal([]byte{0x06, 0x00}))
			Expect(b.Bytes()[7:]).To(Equal([]byte{'f', 'o', 'o', 'b', 'a', 'r'}))
		})

		It("rejects ReasonPhrases that are too long", func() {
			b := &bytes.Buffer{}

			reasonPhrase := strings.Repeat("a", 0xFFFF+0x11)

			frame := &ConnectionCloseFrame{
				ErrorCode:    0xDEADBEEF,
				ReasonPhrase: reasonPhrase,
			}
			err := frame.Write(b, 0)
			Expect(err).To(HaveOccurred())
		})

		It("has proper min length", func() {
			b := &bytes.Buffer{}
			f := &ConnectionCloseFrame{
				ErrorCode:    0xDEADBEEF,
				ReasonPhrase: "foobar",
			}
			f.Write(b, 0)
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
		})
	})

	It("is self-consistent", func() {
		b := &bytes.Buffer{}
		frame := &ConnectionCloseFrame{
			ErrorCode:    0xDEADBEEF,
			ReasonPhrase: "Lorem ipsum dolor sit amet.",
		}
		err := frame.Write(b, 0)
		Expect(err).ToNot(HaveOccurred())
		readframe, err := ParseConnectionCloseFrame(bytes.NewReader(b.Bytes()))
		Expect(err).ToNot(HaveOccurred())
		Expect(readframe.ErrorCode).To(Equal(frame.ErrorCode))
		Expect(readframe.ReasonPhrase).To(Equal(frame.ReasonPhrase))
	})
})
