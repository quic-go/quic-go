package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Retransmission queue", func() {
	const version = protocol.VersionTLS

	var q *retransmissionQueue

	BeforeEach(func() {
		q = newRetransmissionQueue(version)
	})

	Context("Initial data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.HasInitialData()).To(BeFalse())
			Expect(q.GetInitialFrame(protocol.MaxByteCount)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.AddInitial(f)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetInitialFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("queues and retrieves a CRYPTO frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddInitial(f)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("returns split CRYPTO frames", func() {
			f := &wire.CryptoFrame{
				Offset: 100,
				Data:   []byte("foobar"),
			}
			q.AddInitial(f)
			Expect(q.HasInitialData()).To(BeTrue())
			f1 := q.GetInitialFrame(f.Length(version) - 3)
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f1.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
			Expect(f1.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
			Expect(q.HasInitialData()).To(BeTrue())
			f2 := q.GetInitialFrame(protocol.MaxByteCount)
			Expect(f2).ToNot(BeNil())
			Expect(f2).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f2.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
			Expect(f2.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("returns other frames when a CRYPTO frame wouldn't fit", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddInitial(f)
			q.AddInitial(&wire.PingFrame{})
			f1 := q.GetInitialFrame(2) // too small for a CRYPTO frame
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.PingFrame{}))
			Expect(q.HasInitialData()).To(BeTrue())
			f2 := q.GetInitialFrame(protocol.MaxByteCount)
			Expect(f2).To(Equal(f))
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{MaximumData: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddInitial(f)
			q.AddInitial(cf)
			Expect(q.HasInitialData()).To(BeTrue())
			Expect(q.GetInitialFrame(protocol.MaxByteCount)).To(Equal(f))
			Expect(q.GetInitialFrame(protocol.MaxByteCount)).To(Equal(cf))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("drops all Initial frames", func() {
			q.AddInitial(&wire.CryptoFrame{Data: []byte("foobar")})
			q.AddInitial(&wire.MaxDataFrame{MaximumData: 0x42})
			q.DropPackets(protocol.EncryptionInitial)
			Expect(q.HasInitialData()).To(BeFalse())
			Expect(q.GetInitialFrame(protocol.MaxByteCount)).To(BeNil())
		})
	})

	Context("Handshake data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.HasHandshakeData()).To(BeFalse())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			q.AddHandshake(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetHandshakeFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("queues and retrieves a CRYPTO frame", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddHandshake(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("returns split CRYPTO frames", func() {
			f := &wire.CryptoFrame{
				Offset: 100,
				Data:   []byte("foobar"),
			}
			q.AddHandshake(f)
			Expect(q.HasHandshakeData()).To(BeTrue())
			f1 := q.GetHandshakeFrame(f.Length(version) - 3)
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f1.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
			Expect(f1.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
			Expect(q.HasHandshakeData()).To(BeTrue())
			f2 := q.GetHandshakeFrame(protocol.MaxByteCount)
			Expect(f2).ToNot(BeNil())
			Expect(f2).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
			Expect(f2.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
			Expect(f2.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("returns other frames when a CRYPTO frame wouldn't fit", func() {
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddHandshake(f)
			q.AddHandshake(&wire.PingFrame{})
			f1 := q.GetHandshakeFrame(2) // too small for a CRYPTO frame
			Expect(f1).ToNot(BeNil())
			Expect(f1).To(BeAssignableToTypeOf(&wire.PingFrame{}))
			Expect(q.HasHandshakeData()).To(BeTrue())
			f2 := q.GetHandshakeFrame(protocol.MaxByteCount)
			Expect(f2).To(Equal(f))
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{MaximumData: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddHandshake(f)
			q.AddHandshake(cf)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount)).To(Equal(f))
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount)).To(Equal(cf))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("drops all Handshake frames", func() {
			q.AddHandshake(&wire.CryptoFrame{Data: []byte("foobar")})
			q.AddHandshake(&wire.MaxDataFrame{MaximumData: 0x42})
			q.DropPackets(protocol.EncryptionHandshake)
			Expect(q.HasHandshakeData()).To(BeFalse())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount)).To(BeNil())
		})
	})

	Context("Application data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.GetAppDataFrame(protocol.MaxByteCount)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			Expect(q.HasAppData()).To(BeFalse())
			q.AddAppData(f)
			Expect(q.HasAppData()).To(BeTrue())
			Expect(q.GetAppDataFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetAppDataFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasAppData()).To(BeFalse())
		})
	})
})
