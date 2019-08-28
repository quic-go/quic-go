package quic

import (
	"math/rand"

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
			f := &wire.MaxDataFrame{ByteOffset: 0x42}
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
			Expect(q.GetInitialFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetInitialFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasInitialData()).To(BeFalse())
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{ByteOffset: 0x42}
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
			q.AddInitial(&wire.MaxDataFrame{ByteOffset: 0x42})
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
			f := &wire.MaxDataFrame{ByteOffset: 0x42}
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
			Expect(q.GetHandshakeFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetHandshakeFrame(f.Length(version))).To(Equal(f))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("retrieves both a CRYPTO frame and a control frame", func() {
			cf := &wire.MaxDataFrame{ByteOffset: 0x42}
			f := &wire.CryptoFrame{Data: []byte("foobar")}
			q.AddHandshake(f)
			q.AddHandshake(cf)
			Expect(q.HasHandshakeData()).To(BeTrue())
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount)).To(Equal(f))
			Expect(q.GetHandshakeFrame(protocol.MaxByteCount)).To(Equal(cf))
			Expect(q.HasHandshakeData()).To(BeFalse())
		})

		It("drops all Initial frames", func() {
			q.AddHandshake(&wire.CryptoFrame{Data: []byte("foobar")})
			q.AddHandshake(&wire.MaxDataFrame{ByteOffset: 0x42})
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
			f := &wire.MaxDataFrame{ByteOffset: 0x42}
			q.AddAppData(f)
			Expect(q.GetAppDataFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetAppDataFrame(f.Length(version))).To(Equal(f))
		})

		It("queues and retrieves a STREAM frame", func() {
			f := &wire.StreamFrame{Data: []byte("foobar")}
			q.AddAppData(f)
			Expect(q.GetAppDataFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetAppDataFrame(f.Length(version))).To(Equal(f))
		})

		It("splits STREAM frames larger than MinStreamFrameSize", func() {
			data := make([]byte, 1000)
			rand.Read(data)
			f := &wire.StreamFrame{
				Data:   data,
				FinBit: true,
			}
			q.AddAppData(f)
			Expect(q.GetAppDataFrame(protocol.MinStreamFrameSize - 1)).To(BeNil())
			f1 := q.GetAppDataFrame(protocol.MinStreamFrameSize).(*wire.StreamFrame)
			Expect(f1).ToNot(BeNil())
			Expect(f1.Length(version)).To(Equal(protocol.MinStreamFrameSize))
			Expect(f1.FinBit).To(BeFalse())
			Expect(f1.Data).To(Equal(data[:f1.DataLen()]))
			f2 := q.GetAppDataFrame(protocol.MaxByteCount).(*wire.StreamFrame)
			Expect(f2).ToNot(BeNil())
			Expect(f2.FinBit).To(BeTrue())
			Expect(f1.DataLen() + f2.DataLen()).To(BeEquivalentTo(1000))
			Expect(f2.Data).To(Equal(data[f1.DataLen():]))
			Expect(q.GetAppDataFrame(protocol.MaxByteCount)).To(BeNil())
		})

		It("returns a control frame if it doesn't split a STREAM frame", func() {
			cf := &wire.MaxDataFrame{ByteOffset: 0x42}
			q.AddAppData(&wire.StreamFrame{Data: make([]byte, 1000)})
			q.AddAppData(cf)
			Expect(q.GetAppDataFrame(protocol.MinStreamFrameSize - 1)).To(Equal(cf))
		})
	})
})
