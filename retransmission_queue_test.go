package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Retransmission queue", func() {
	var q *retransmissionQueue

	BeforeEach(func() {
		q = newRetransmissionQueue()
	})

	Context("Initial data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeFalse())
			Expect(q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.addInitial(f)
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionInitial, f.Length(protocol.Version1)-1, protocol.Version1)).To(BeNil())
			Expect(q.GetFrame(protocol.EncryptionInitial, f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeFalse())
		})

		It("queues and retrieves a CRYPTO frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addInitial(f)
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionInitial, f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeFalse())
		})

		It("returns split CRYPTO frames", func() {
			f := &wire.CryptoFrame{
				Offset: 100,
				Data:   []byte("foobar"),
			}
			q.addInitial(f)
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			f1 := q.GetFrame(protocol.EncryptionInitial, f.Length(protocol.Version1)-3, protocol.Version1)
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f1.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
			Expect(f1.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			f2 := q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)
			Expect(f2).ToNot(BeNil())
			Expect(f2).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f2.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
			Expect(f2.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeFalse())
		})

		It("returns other frames when a CRYPTO frame wouldn't fit", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addInitial(f)
			q.addInitial(&wire.PingFrame{})
			f1 := q.GetFrame(protocol.EncryptionInitial, 2, protocol.Version1) // too small for a CRYPTO frame
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.PingFrame{}))
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			f2 := q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)
			Expect(f2).To(Equal(f))
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{MaximumData: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addInitial(f)
			q.addInitial(cf)
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
			Expect(q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)).To(Equal(cf))
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeFalse())
		})

		It("drops all Initial frames", func() {
			q.addInitial(&wire.CryptoFrame{Data: []byte("foobar")})
			q.addInitial(&wire.MaxDataFrame{MaximumData: 0x42})
			q.DropPackets(protocol.EncryptionInitial)
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeFalse())
			Expect(q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("retransmits a frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.AckHandler(protocol.EncryptionInitial).OnLost(f)
			Expect(q.HasData(protocol.EncryptionInitial)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionInitial, protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
		})
	})

	Context("Handshake data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeFalse())
			Expect(q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.addHandshake(f)
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionHandshake, f.Length(protocol.Version1)-1, protocol.Version1)).To(BeNil())
			Expect(q.GetFrame(protocol.EncryptionHandshake, f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeFalse())
		})

		It("queues and retrieves a CRYPTO frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addHandshake(f)
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionHandshake, f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeFalse())
		})

		It("returns split CRYPTO frames", func() {
			f := &wire.CryptoFrame{
				Offset: 100,
				Data:   []byte("foobar"),
			}
			q.addHandshake(f)
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			f1 := q.GetFrame(protocol.EncryptionHandshake, f.Length(protocol.Version1)-3, protocol.Version1)
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f1.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
			Expect(f1.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			f2 := q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)
			Expect(f2).ToNot(BeNil())
			Expect(f2).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f2.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
			Expect(f2.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeFalse())
		})

		It("returns other frames when a CRYPTO frame wouldn't fit", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addHandshake(f)
			q.addHandshake(&wire.PingFrame{})
			f1 := q.GetFrame(protocol.EncryptionHandshake, 2, protocol.Version1) // too small for a CRYPTO frame
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.PingFrame{}))
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			f2 := q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)
			Expect(f2).To(Equal(f))
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{MaximumData: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addHandshake(f)
			q.addHandshake(cf)
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
			Expect(q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)).To(Equal(cf))
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeFalse())
		})

		It("drops all Handshake frames", func() {
			q.addHandshake(&wire.CryptoFrame{Data: []byte("foobar")})
			q.addHandshake(&wire.MaxDataFrame{MaximumData: 0x42})
			q.DropPackets(protocol.EncryptionHandshake)
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeFalse())
			Expect(q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("retransmits a frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.AckHandler(protocol.EncryptionHandshake).OnLost(f)
			Expect(q.HasData(protocol.EncryptionHandshake)).To(BeTrue())
			Expect(q.GetFrame(protocol.EncryptionHandshake, protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
		})
	})

	Context("Application data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.HasData(protocol.Encryption1RTT)).To(BeFalse())
			Expect(q.GetFrame(protocol.Encryption1RTT, protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			Expect(q.HasData(protocol.Encryption1RTT)).To(BeFalse())
			q.addAppData(f)
			Expect(q.HasData(protocol.Encryption1RTT)).To(BeTrue())
			Expect(q.GetFrame(protocol.Encryption1RTT, f.Length(protocol.Version1)-1, protocol.Version1)).To(BeNil())
			Expect(q.GetFrame(protocol.Encryption1RTT, f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasData(protocol.Encryption1RTT)).To(BeFalse())
		})

		It("retransmits a frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.AckHandler(protocol.Encryption1RTT).OnLost(f)
			Expect(q.HasData(protocol.Encryption1RTT)).To(BeTrue())
			Expect(q.GetFrame(protocol.Encryption1RTT, protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
		})
	})
})
