package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto Stream", func() {
	var (
		str cryptoStream
	)

	BeforeEach(func() {
		str = newCryptoStream()
	})

	Context("handling incoming data", func() {
		It("handles in-order CRYPTO frames", func() {
			err := str.HandleCryptoFrame(&wire.CryptoFrame{
				Data: []byte("foobar"),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(Equal([]byte("foobar")))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		It("errors if the frame exceeds the maximum offset", func() {
			err := str.HandleCryptoFrame(&wire.CryptoFrame{
				Offset: protocol.MaxCryptoStreamOffset - 5,
				Data:   []byte("foobar"),
			})
			Expect(err).To(MatchError(fmt.Sprintf("received invalid offset %d on crypto stream, maximum allowed %d", protocol.MaxCryptoStreamOffset+1, protocol.MaxCryptoStreamOffset)))
		})

		It("handles out-of-order CRYPTO frames", func() {
			err := str.HandleCryptoFrame(&wire.CryptoFrame{
				Offset: 3,
				Data:   []byte("bar"),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(BeNil())
			err = str.HandleCryptoFrame(&wire.CryptoFrame{
				Data: []byte("foo"),
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(Equal([]byte("foo")))
			Expect(str.GetCryptoData()).To(Equal([]byte("bar")))
			Expect(str.GetCryptoData()).To(BeNil())
		})
	})

	Context("writing data", func() {
		It("says if it has data", func() {
			Expect(str.HasData()).To(BeFalse())
			_, err := str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			Expect(str.HasData()).To(BeTrue())
		})

		It("pops crypto frames", func() {
			_, err := str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			f := str.PopCryptoFrame(1000)
			Expect(f).ToNot(BeNil())
			Expect(f.Offset).To(BeZero())
			Expect(f.Data).To(Equal([]byte("foobar")))
		})

		It("coalesces multiple writes", func() {
			_, err := str.Write([]byte("foo"))
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write([]byte("bar"))
			Expect(err).ToNot(HaveOccurred())
			f := str.PopCryptoFrame(1000)
			Expect(f).ToNot(BeNil())
			Expect(f.Offset).To(BeZero())
			Expect(f.Data).To(Equal([]byte("foobar")))
		})

		It("respects the maximum size", func() {
			frameHeaderLen := (&wire.CryptoFrame{}).Length(protocol.VersionWhatever)
			_, err := str.Write([]byte("foobar"))
			Expect(err).ToNot(HaveOccurred())
			f := str.PopCryptoFrame(frameHeaderLen + 3)
			Expect(f).ToNot(BeNil())
			Expect(f.Offset).To(BeZero())
			Expect(f.Data).To(Equal([]byte("foo")))
			f = str.PopCryptoFrame(frameHeaderLen + 3)
			Expect(f).ToNot(BeNil())
			Expect(f.Offset).To(Equal(protocol.ByteCount(3)))
			Expect(f.Data).To(Equal([]byte("bar")))
		})
	})
})
