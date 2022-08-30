package wire

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Short Header", func() {
	Context("Parsing", func() {
		It("parses", func() {
			data := []byte{
				0b01000110,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37, 0x99,
			}
			hdr, err := ParseShortHeader(data, 4)
			Expect(err).ToNot(HaveOccurred())
			Expect(hdr.DestConnectionID).To(Equal(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})))
			Expect(hdr.KeyPhase).To(Equal(protocol.KeyPhaseOne))
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x133799)))
			Expect(hdr.PacketNumberLen).To(Equal(protocol.PacketNumberLen3))
		})

		It("errors when the QUIC bit is not set", func() {
			data := []byte{
				0b00000101,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37,
			}
			_, err := ParseShortHeader(data, 4)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("errors, but returns the header, when the reserved bits are set", func() {
			data := []byte{
				0b01010101,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37,
			}
			hdr, err := ParseShortHeader(data, 4)
			Expect(err).To(MatchError(ErrInvalidReservedBits))
			Expect(hdr).ToNot(BeNil())
			Expect(hdr.PacketNumber).To(Equal(protocol.PacketNumber(0x1337)))
		})

		It("errors when passed a long header packet", func() {
			_, err := ParseShortHeader([]byte{0x80}, 4)
			Expect(err).To(MatchError("not a short header packet"))
		})

		It("errors on EOF", func() {
			data := []byte{
				0b01000110,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37, 0x99,
			}
			_, err := ParseShortHeader(data, 4)
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				_, err := ParseShortHeader(data[:i], 4)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("logging", func() {
		var (
			buf    *bytes.Buffer
			logger utils.Logger
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			logger = utils.DefaultLogger
			logger.SetLogLevel(utils.LogLevelDebug)
			log.SetOutput(buf)
		})

		AfterEach(func() {
			log.SetOutput(os.Stdout)
		})

		It("logs Short Headers containing a connection ID", func() {
			(&ShortHeader{
				DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37}),
				KeyPhase:         protocol.KeyPhaseOne,
				PacketNumber:     1337,
				PacketNumberLen:  4,
			}).Log(logger)
			Expect(buf.String()).To(ContainSubstring("Short Header{DestConnectionID: deadbeefcafe1337, PacketNumber: 1337, PacketNumberLen: 4, KeyPhase: 1}"))
		})
	})

	It("determines the length", func() {
		Expect((&ShortHeader{
			DestConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xaf}),
			PacketNumber:     0x1337,
			PacketNumberLen:  protocol.PacketNumberLen3,
			KeyPhase:         protocol.KeyPhaseOne,
		}).Len()).To(Equal(protocol.ByteCount(1 + 2 + 3)))
	})
})
