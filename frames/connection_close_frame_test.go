package frames

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConnectionCloseFrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			b := bytes.NewReader([]byte{0x40, 0x19, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x4e, 0x6f, 0x20, 0x72, 0x65, 0x63, 0x65, 0x6e, 0x74, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x2e})
			frame, err := ParseConnectionCloseFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ErrorCode).To(Equal(protocol.ErrorCode(0x19)))
			Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
			Expect(b.Len()).To(Equal(0))
		})

		It("parses a frame without a reason phrase", func() {
			b := bytes.NewReader([]byte{0x02, 0xAD, 0xFB, 0xCA, 0xDE, 0x00, 0x00})
			frame, err := ParseConnectionCloseFrame(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ErrorCode).To(Equal(protocol.ErrorCode(0xDECAFBAD)))
			Expect(len(frame.ReasonPhrase)).To(Equal(0))
			Expect(b.Len()).To(Equal(0))
		})
	})

	Context("when writing", func() {
		It("writes a frame without a ReasonPhrase", func() {
			b := &bytes.Buffer{}
			frame := &ConnectionCloseFrame{
				ErrorCode: 0xDEADBEEF,
			}
			err := frame.Write(b)
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
			err := frame.Write(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(Equal(1 + 2 + 4 + len(frame.ReasonPhrase)))
			Expect(b.Bytes()[:5]).To(Equal([]byte{0x02, 0xEF, 0xBE, 0xAD, 0xDE}))
			Expect(b.Bytes()[5:7]).To(Equal([]byte{0x06, 0x00}))
			Expect(b.Bytes()[7:]).To(Equal([]byte{'f', 'o', 'o', 'b', 'a', 'r'}))
		})

		It("rejects ReasonPhrases that are too long", func() {
			b := &bytes.Buffer{}

			var reasonPhrase string
			for i := 0; i < int(0xFFFF+0x11); i++ {
				reasonPhrase += "a"
			}

			frame := &ConnectionCloseFrame{
				ErrorCode:    0xDEADBEEF,
				ReasonPhrase: reasonPhrase,
			}
			err := frame.Write(b)
			Expect(err).To(HaveOccurred())
		})

		It("has proper max length", func() {
			b := &bytes.Buffer{}
			f := &ConnectionCloseFrame{
				ErrorCode:    0xDEADBEEF,
				ReasonPhrase: "foobar",
			}
			f.Write(b)
			Expect(f.MaxLength()).To(Equal(b.Len()))
		})
	})

	It("is self-consistent", func() {
		b := &bytes.Buffer{}
		frame := &ConnectionCloseFrame{
			ErrorCode:    0xDEADBEEF,
			ReasonPhrase: "Lorem ipsum dolor sit amet.",
		}
		err := frame.Write(b)
		Expect(err).ToNot(HaveOccurred())
		readframe, err := ParseConnectionCloseFrame(bytes.NewReader(b.Bytes()))
		Expect(err).ToNot(HaveOccurred())
		Expect(readframe.ErrorCode).To(Equal(frame.ErrorCode))
		Expect(readframe.ReasonPhrase).To(Equal(frame.ReasonPhrase))
	})
})
