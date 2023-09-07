package quic

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Crypto Stream", func() {
	var str cryptoStream

	BeforeEach(func() {
		str = newCryptoStream()
	})

	Context("handling incoming data", func() {
		It("handles in-order CRYPTO frames", func() {
			Expect(str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")})).To(Succeed())
			Expect(str.GetCryptoData()).To(Equal([]byte("foo")))
			Expect(str.GetCryptoData()).To(BeNil())
			Expect(str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3})).To(Succeed())
			Expect(str.GetCryptoData()).To(Equal([]byte("bar")))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		It("errors if the frame exceeds the maximum offset", func() {
			Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
				Offset: protocol.MaxCryptoStreamOffset - 5,
				Data:   []byte("foobar"),
			})).To(MatchError(&qerr.TransportError{
				ErrorCode:    qerr.CryptoBufferExceeded,
				ErrorMessage: fmt.Sprintf("received invalid offset %d on crypto stream, maximum allowed %d", protocol.MaxCryptoStreamOffset+1, protocol.MaxCryptoStreamOffset),
			}))
		})

		It("handles out-of-order CRYPTO frames", func() {
			Expect(str.HandleCryptoFrame(&wire.CryptoFrame{Offset: 3, Data: []byte("bar")})).To(Succeed())
			Expect(str.HandleCryptoFrame(&wire.CryptoFrame{Data: []byte("foo")})).To(Succeed())
			Expect(str.GetCryptoData()).To(Equal([]byte("foobar")))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		Context("finishing", func() {
			It("errors if there's still data to read after finishing", func() {
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Data:   []byte("foobar"),
					Offset: 10,
				})).To(Succeed())
				Expect(str.Finish()).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: "encryption level changed, but crypto stream has more data to read",
				}))
			})

			It("works with reordered data", func() {
				f1 := &wire.CryptoFrame{
					Data: []byte("foo"),
				}
				f2 := &wire.CryptoFrame{
					Offset: 3,
					Data:   []byte("bar"),
				}
				Expect(str.HandleCryptoFrame(f2)).To(Succeed())
				Expect(str.HandleCryptoFrame(f1)).To(Succeed())
				Expect(str.Finish()).To(Succeed())
				Expect(str.HandleCryptoFrame(f2)).To(Succeed())
			})

			It("rejects new crypto data after finishing", func() {
				Expect(str.Finish()).To(Succeed())
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Data: []byte("foo"),
				})).To(MatchError(&qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: "received crypto data after change of encryption level",
				}))
			})

			It("ignores crypto data below the maximum offset received before finishing", func() {
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Data: []byte("foobar"),
				})).To(Succeed())
				Expect(str.GetCryptoData()).To(Equal([]byte("foobar")))
				Expect(str.Finish()).To(Succeed())
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Offset: 2,
					Data:   []byte("foo"),
				})).To(Succeed())
			})
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
			frameHeaderLen := (&wire.CryptoFrame{}).Length(protocol.Version1)
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
