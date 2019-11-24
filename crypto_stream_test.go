package quic

import (
	"crypto/rand"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func createHandshakeMessage(len int) []byte {
	msg := make([]byte, 4+len)
	rand.Read(msg[:1]) // random message type
	msg[1] = uint8(len >> 16)
	msg[2] = uint8(len >> 8)
	msg[3] = uint8(len)
	rand.Read(msg[4:])
	return msg
}

var _ = Describe("Crypto Stream", func() {
	var (
		str cryptoStream
	)

	BeforeEach(func() {
		str = newCryptoStream()
	})

	Context("handling incoming data", func() {
		It("handles in-order CRYPTO frames", func() {
			msg := createHandshakeMessage(6)
			err := str.HandleCryptoFrame(&wire.CryptoFrame{Data: msg})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(Equal(msg))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		It("handles multiple messages in one CRYPTO frame", func() {
			msg1 := createHandshakeMessage(6)
			msg2 := createHandshakeMessage(10)
			msg := append(append([]byte{}, msg1...), msg2...)
			err := str.HandleCryptoFrame(&wire.CryptoFrame{Data: msg})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(Equal(msg1))
			Expect(str.GetCryptoData()).To(Equal(msg2))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		It("errors if the frame exceeds the maximum offset", func() {
			err := str.HandleCryptoFrame(&wire.CryptoFrame{
				Offset: protocol.MaxCryptoStreamOffset - 5,
				Data:   []byte("foobar"),
			})
			Expect(err).To(MatchError(fmt.Sprintf("CRYPTO_BUFFER_EXCEEDED: received invalid offset %d on crypto stream, maximum allowed %d", protocol.MaxCryptoStreamOffset+1, protocol.MaxCryptoStreamOffset)))
		})

		It("handles messages split over multiple CRYPTO frames", func() {
			msg := createHandshakeMessage(6)
			err := str.HandleCryptoFrame(&wire.CryptoFrame{
				Data: msg[:4],
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(BeNil())
			err = str.HandleCryptoFrame(&wire.CryptoFrame{
				Offset: 4,
				Data:   msg[4:],
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(Equal(msg))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		It("handles out-of-order CRYPTO frames", func() {
			msg := createHandshakeMessage(6)
			err := str.HandleCryptoFrame(&wire.CryptoFrame{
				Offset: 4,
				Data:   msg[4:],
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(BeNil())
			err = str.HandleCryptoFrame(&wire.CryptoFrame{
				Data: msg[:4],
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(str.GetCryptoData()).To(Equal(msg))
			Expect(str.GetCryptoData()).To(BeNil())
		})

		Context("finishing", func() {
			It("errors if there's still data to read after finishing", func() {
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Data:   createHandshakeMessage(5),
					Offset: 10,
				})).To(Succeed())
				err := str.Finish()
				Expect(err).To(MatchError("encryption level changed, but crypto stream has more data to read"))
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
				err := str.HandleCryptoFrame(&wire.CryptoFrame{
					Data: createHandshakeMessage(5),
				})
				Expect(err).To(MatchError("PROTOCOL_VIOLATION: received crypto data after change of encryption level"))
			})

			It("ignores crypto data below the maximum offset received before finishing", func() {
				msg := createHandshakeMessage(15)
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Data: msg,
				})).To(Succeed())
				Expect(str.GetCryptoData()).To(Equal(msg))
				Expect(str.Finish()).To(Succeed())
				Expect(str.HandleCryptoFrame(&wire.CryptoFrame{
					Offset: protocol.ByteCount(len(msg) - 6),
					Data:   []byte("foobar"),
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

var _ = Describe("Post Handshake Crypto Stream", func() {
	var (
		cs     cryptoStream
		framer framer
	)

	BeforeEach(func() {
		framer = newFramer(NewMockStreamGetter(mockCtrl), protocol.VersionTLS)
		cs = newPostHandshakeCryptoStream(framer)
	})

	It("queues CRYPTO frames when writing data", func() {
		n, err := cs.Write([]byte("foo"))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		n, err = cs.Write([]byte("bar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		frames, _ := framer.AppendControlFrames(nil, 1000)
		Expect(frames).To(HaveLen(2))
		fs := []wire.Frame{frames[0].Frame, frames[1].Frame}
		Expect(fs).To(ContainElement(&wire.CryptoFrame{Data: []byte("foo")}))
		Expect(fs).To(ContainElement(&wire.CryptoFrame{Data: []byte("bar"), Offset: 3}))
	})

	It("splits large writes into multiple frames", func() {
		size := 10 * protocol.MaxPostHandshakeCryptoFrameSize
		n, err := cs.Write(make([]byte, size))
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(BeEquivalentTo(size))
		frames, _ := framer.AppendControlFrames(nil, protocol.MaxByteCount)
		Expect(frames).To(HaveLen(11)) // one more for framing overhead
		var dataLen int
		for _, f := range frames {
			Expect(f.Frame.Length(protocol.VersionTLS)).To(BeNumerically("<=", protocol.MaxPostHandshakeCryptoFrameSize))
			Expect(f.Frame).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			dataLen += len(f.Frame.(*wire.CryptoFrame).Data)
		}
		Expect(dataLen).To(BeEquivalentTo(size))
	})

})
