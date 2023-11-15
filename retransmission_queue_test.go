package quic

import (
	"github.com/Psiphon-Labs/quic-go/internal/protocol"
	"github.com/Psiphon-Labs/quic-go/internal/wire"

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
			Expect(q.HasInitialData()).To(BeFalse())
			Expect(q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.addInitial(f)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(f.Length(protocol.Version1)-1, protocol.Version1)).To(BeNil())
			Expect(q.GetInitialFrame(f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("queues and retrieves a CRYPTO frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addInitial(f)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("returns split CRYPTO frames", func() {
			f := &wire.CryptoFrame{
				Offset: 100,
				Data:   []byte("foobar"),
			}
			q.addInitial(f)
			Expect(q.HasInitialData()).To(BeTrue())
			f1 := q.GetInitialFrame(f.Length(protocol.Version1)-3, protocol.Version1)
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f1.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
			Expect(f1.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
			Expect(q.HasInitialData()).To(BeTrue())
			f2 := q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(f2).ToNot(BeNil())
			Expect(f2).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f2.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
			Expect(f2.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("returns other frames when a CRYPTO frame wouldn't fit", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addInitial(f)
			q.addInitial(&wire.PingFrame{})
			f1 := q.GetInitialFrame(2, protocol.Version1) // too small for a CRYPTO frame
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.PingFrame{}))
			Expect(q.HasInitialData()).To(BeTrue())
			f2 := q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(f2).To(Equal(f))
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{MaximumData: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addInitial(f)
			q.addInitial(cf)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
			Expect(q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(cf))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("drops all Initial frames", func() {
			q.addInitial(&wire.CryptoFrame{Data: []byte("foobar")})
			q.addInitial(&wire.MaxDataFrame{MaximumData: 0x42})
			q.DropPackets(protocol.EncryptionInitial)
			Expect(q.HasInitialData()).To(BeFalse())
			Expect(q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("retransmits a frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.InitialAckHandler().OnLost(f)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
		})

		It("adds a PING", func() {
			q.AddPing(protocol.EncryptionInitial)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(&wire.PingFrame{}))
		})
	})

	Context("Handshake data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.HasHandshakeData()).To(BeFalse())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.addHandshake(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(f.Length(protocol.Version1)-1, protocol.Version1)).To(BeNil())
			Expect(q.GetHandshakeFrame(f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("queues and retrieves a CRYPTO frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addHandshake(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("returns split CRYPTO frames", func() {
			f := &wire.CryptoFrame{
				Offset: 100,
				Data:   []byte("foobar"),
			}
			q.addHandshake(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			f1 := q.GetHandshakeFrame(f.Length(protocol.Version1)-3, protocol.Version1)
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f1.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
			Expect(f1.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
			Expect(q.HasHandshakeData()).To(BeTrue())
			f2 := q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(f2).ToNot(BeNil())
			Expect(f2).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f2.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
			Expect(f2.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("returns other frames when a CRYPTO frame wouldn't fit", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addHandshake(f)
			q.addHandshake(&wire.PingFrame{})
			f1 := q.GetHandshakeFrame(2, protocol.Version1) // too small for a CRYPTO frame
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.PingFrame{}))
			Expect(q.HasHandshakeData()).To(BeTrue())
			f2 := q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)
			Expect(f2).To(Equal(f))
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{MaximumData: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.addHandshake(f)
			q.addHandshake(cf)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(cf))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("drops all Handshake frames", func() {
			q.addHandshake(&wire.CryptoFrame{Data: []byte("foobar")})
			q.addHandshake(&wire.MaxDataFrame{MaximumData: 0x42})
			q.DropPackets(protocol.EncryptionHandshake)
			Expect(q.HasHandshakeData()).To(BeFalse())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("retransmits a frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.HandshakeAckHandler().OnLost(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
		})

		It("adds a PING", func() {
			q.AddPing(protocol.EncryptionHandshake)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(&wire.PingFrame{}))
		})
	})

	Context("Application data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.GetAppDataFrame(protocol.MaxByteCount, protocol.Version1)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			Expect(q.HasAppData()).To(BeFalse())
			q.addAppData(f)
			Expect(q.HasAppData()).To(BeTrue())
			Expect(q.GetAppDataFrame(f.Length(protocol.Version1)-1, protocol.Version1)).To(BeNil())
			Expect(q.GetAppDataFrame(f.Length(protocol.Version1), protocol.Version1)).To(Equal(f))
			Expect(q.HasAppData()).To(BeFalse())
		})

		It("retransmits a frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.AppDataAckHandler().OnLost(f)
			Expect(q.HasAppData()).To(BeTrue())
			Expect(q.GetAppDataFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(f))
		})

		It("adds a PING", func() {
			q.AddPing(protocol.Encryption1RTT)
			Expect(q.HasAppData()).To(BeTrue())
			Expect(q.GetAppDataFrame(protocol.MaxByteCount, protocol.Version1)).To(Equal(&wire.PingFrame{}))
		})
	})
})
