package wire

import (
	"bytes"
	"strings"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ConnectionCloseFrame", func() {
	Context("when parsing", func() {
		Context("in little endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x2,
					0x19, 0x0, 0x0, 0x0, // error code
					0x1b, 0x0, // reason phrase length
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				})
				frame, err := ParseConnectionCloseFrame(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.ErrorCode).To(Equal(qerr.ErrorCode(0x19)))
				Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects long reason phrases", func() {
				b := bytes.NewReader([]byte{0x2,
					0xad, 0xfb, 0xca, 0xde, // error code
					0x0, 0xff, // reason phrase length
				})
				_, err := ParseConnectionCloseFrame(b, versionLittleEndian)
				Expect(err).To(MatchError(qerr.Error(qerr.InvalidConnectionCloseData, "reason phrase too long")))
			})

			It("errors on EOFs", func() {
				data := []byte{0x2,
					0x19, 0x0, 0x0, 0x0, // error code
					0x1b, 0x0, // reason phrase length
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				}
				_, err := ParseConnectionCloseFrame(bytes.NewReader(data), versionLittleEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := ParseConnectionCloseFrame(bytes.NewReader(data[0:i]), versionLittleEndian)
					Expect(err).To(HaveOccurred())
				}
			})
		})

		Context("in big endian", func() {
			It("accepts sample frame", func() {
				b := bytes.NewReader([]byte{0x2,
					0x0, 0x0, 0x0, 0x19, // error code
					0x0, 0x1b, // reason phrase length
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				})
				frame, err := ParseConnectionCloseFrame(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(frame.ErrorCode).To(Equal(qerr.ErrorCode(0x19)))
				Expect(frame.ReasonPhrase).To(Equal("No recent network activity."))
				Expect(b.Len()).To(BeZero())
			})

			It("rejects long reason phrases", func() {
				b := bytes.NewReader([]byte{0x2,
					0xad, 0xfb, 0xca, 0xde, // error code
					0xff, 0x0, // reason phrase length
				})
				_, err := ParseConnectionCloseFrame(b, versionBigEndian)
				Expect(err).To(MatchError(qerr.Error(qerr.InvalidConnectionCloseData, "reason phrase too long")))
			})

			It("errors on EOFs", func() {
				data := []byte{0x40,
					0x19, 0x0, 0x0, 0x0, // error code
					0x0, 0x1b, // reason phrase length
					'N', 'o', ' ', 'r', 'e', 'c', 'e', 'n', 't', ' ', 'n', 'e', 't', 'w', 'o', 'r', 'k', ' ', 'a', 'c', 't', 'i', 'v', 'i', 't', 'y', '.',
				}
				_, err := ParseConnectionCloseFrame(bytes.NewReader(data), versionBigEndian)
				Expect(err).NotTo(HaveOccurred())
				for i := range data {
					_, err := ParseConnectionCloseFrame(bytes.NewReader(data[0:i]), versionBigEndian)
					Expect(err).To(HaveOccurred())
				}
			})
		})

		It("parses a frame without a reason phrase", func() {
			b := bytes.NewReader([]byte{0x2,
				0xad, 0xfb, 0xca, 0xde, // error code
				0x0, 0x0, // reason phrase length
			})
			frame, err := ParseConnectionCloseFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.ReasonPhrase).To(BeEmpty())
			Expect(b.Len()).To(BeZero())
		})
	})

	Context("when writing", func() {
		Context("in little endian", func() {
			It("writes a frame without a reason phrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode: 0xdeadbeef,
				}
				err := frame.Write(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(1 + 2 + 4))
				Expect(b.Bytes()).To(Equal([]byte{0x2,
					0xef, 0xbe, 0xad, 0xde, // error code
					0x0, 0x0, // reason phrase length
				}))
			})

			It("writes a frame with a reason phrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode:    0xdeadbeef,
					ReasonPhrase: "foobar",
				}
				err := frame.Write(b, versionLittleEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(1 + 2 + 4 + len(frame.ReasonPhrase)))
				Expect(b.Bytes()).To(Equal([]byte{0x2,
					0xef, 0xbe, 0xad, 0xde, // error code
					0x6, 0x0, // reason phrase length
					'f', 'o', 'o', 'b', 'a', 'r',
				}))
			})
		})

		Context("in big endian", func() {
			It("writes a frame without a ReasonPhrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode: 0xdeadbeef,
				}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(1 + 2 + 4))
				Expect(b.Bytes()).To(Equal([]byte{0x2,
					0xde, 0xad, 0xbe, 0xef, // error code
					0x0, 0x0, // reason phrase length
				}))
			})

			It("writes a frame with a ReasonPhrase", func() {
				b := &bytes.Buffer{}
				frame := &ConnectionCloseFrame{
					ErrorCode:    0xdeadbeef,
					ReasonPhrase: "foobar",
				}
				err := frame.Write(b, versionBigEndian)
				Expect(err).ToNot(HaveOccurred())
				Expect(b.Len()).To(Equal(1 + 2 + 4 + len(frame.ReasonPhrase)))
				Expect(b.Bytes()).To(Equal([]byte{0x2,
					0xde, 0xad, 0xbe, 0xef, // error code
					0x0, 0x6, // reason phrase length
					'f', 'o', 'o', 'b', 'a', 'r',
				}))
			})
		})

		It("rejects ReasonPhrases that are too long", func() {
			b := &bytes.Buffer{}
			reasonPhrase := strings.Repeat("a", 0xffff+0x11)
			frame := &ConnectionCloseFrame{
				ErrorCode:    0xdeadbeef,
				ReasonPhrase: reasonPhrase,
			}
			err := frame.Write(b, protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
		})

		It("has proper min length", func() {
			b := &bytes.Buffer{}
			f := &ConnectionCloseFrame{
				ErrorCode:    0xdeadbeef,
				ReasonPhrase: "foobar",
			}
			err := f.Write(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(f.MinLength(0)).To(Equal(protocol.ByteCount(b.Len())))
		})
	})

	It("is self-consistent", func() {
		buf := &bytes.Buffer{}
		frame := &ConnectionCloseFrame{
			ErrorCode:    0xdeadbeef,
			ReasonPhrase: "Lorem ipsum dolor sit amet.",
		}
		err := frame.Write(buf, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		b := bytes.NewReader(buf.Bytes())
		readframe, err := ParseConnectionCloseFrame(b, protocol.VersionWhatever)
		Expect(err).ToNot(HaveOccurred())
		Expect(readframe.ErrorCode).To(Equal(frame.ErrorCode))
		Expect(readframe.ReasonPhrase).To(Equal(frame.ReasonPhrase))
		Expect(b.Len()).To(BeZero())
	})
})
