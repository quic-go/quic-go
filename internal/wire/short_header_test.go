package wire

import (
	"bytes"
	"io"
	"log"
	"os"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	. "github.com/onsi/ginkgo/v2"
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
			l, pn, pnLen, kp, err := ParseShortHeader(data, 4)
			Expect(err).ToNot(HaveOccurred())
			Expect(l).To(Equal(len(data)))
			Expect(kp).To(Equal(protocol.KeyPhaseOne))
			Expect(pn).To(Equal(protocol.PacketNumber(0x133799)))
			Expect(pnLen).To(Equal(protocol.PacketNumberLen3))
		})

		It("errors when the QUIC bit is not set", func() {
			data := []byte{
				0b00000101,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37,
			}
			_, _, _, _, err := ParseShortHeader(data, 4)
			Expect(err).To(MatchError("not a QUIC packet"))
		})

		It("errors, but returns the header, when the reserved bits are set", func() {
			data := []byte{
				0b01010101,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37,
			}
			_, pn, _, _, err := ParseShortHeader(data, 4)
			Expect(err).To(MatchError(ErrInvalidReservedBits))
			Expect(pn).To(Equal(protocol.PacketNumber(0x1337)))
		})

		It("errors when passed a long header packet", func() {
			_, _, _, _, err := ParseShortHeader([]byte{0x80}, 4)
			Expect(err).To(MatchError("not a short header packet"))
		})

		It("errors on EOF", func() {
			data := []byte{
				0b01000110,
				0xde, 0xad, 0xbe, 0xef,
				0x13, 0x37, 0x99,
			}
			_, _, _, _, err := ParseShortHeader(data, 4)
			Expect(err).ToNot(HaveOccurred())
			for i := range data {
				_, _, _, _, err := ParseShortHeader(data[:i], 4)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	It("determines the length", func() {
		Expect(ShortHeaderLen(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), protocol.PacketNumberLen3)).To(BeEquivalentTo(8))
		Expect(ShortHeaderLen(protocol.ParseConnectionID([]byte{}), protocol.PacketNumberLen1)).To(BeEquivalentTo(2))
	})

	Context("writing", func() {
		It("writes a short header packet", func() {
			connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
			b, err := AppendShortHeader(nil, connID, 1337, 4, protocol.KeyPhaseOne)
			Expect(err).ToNot(HaveOccurred())
			l, pn, pnLen, kp, err := ParseShortHeader(b, 4)
			Expect(err).ToNot(HaveOccurred())
			Expect(pn).To(Equal(protocol.PacketNumber(1337)))
			Expect(pnLen).To(Equal(protocol.PacketNumberLen4))
			Expect(kp).To(Equal(protocol.KeyPhaseOne))
			Expect(l).To(Equal(len(b)))
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
			connID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37})
			LogShortHeader(logger, connID, 1337, protocol.PacketNumberLen4, protocol.KeyPhaseOne)
			Expect(buf.String()).To(ContainSubstring("Short Header{DestConnectionID: deadbeefcafe1337, PacketNumber: 1337, PacketNumberLen: 4, KeyPhase: 1}"))
		})
	})
})

func BenchmarkWriteShortHeader(b *testing.B) {
	b.ReportAllocs()
	buf := make([]byte, 100)
	connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6})
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = AppendShortHeader(buf, connID, 1337, protocol.PacketNumberLen4, protocol.KeyPhaseOne)
		if err != nil {
			b.Fatalf("failed to write short header: %s", err)
		}
		buf = buf[:0]
	}
}
