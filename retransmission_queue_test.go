package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/ackhandler"
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

	for _, el := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		encLevel := el

		name := "Initial Data"
		if encLevel == protocol.EncryptionHandshake {
			name = "Handshake Data"
		}

		Context(name, func() {
			var add func(*ackhandler.Frame)
			var hasData func() bool
			var getFrame func(protocol.ByteCount) *ackhandler.Frame

			BeforeEach(func() {
				switch encLevel {
				case protocol.EncryptionInitial:
					add = q.AddInitial
					hasData = q.HasInitialData
					getFrame = q.GetInitialFrame
				case protocol.EncryptionHandshake:
					add = q.AddHandshake
					hasData = q.HasHandshakeData
					getFrame = q.GetHandshakeFrame
				}
			})

			It("doesn't dequeue anything when it's empty", func() {
				Expect(hasData()).To(BeFalse())
				Expect(getFrame(protocol.MaxByteCount)).To(BeNil())
			})

			It("queues and retrieves a control frame", func() {
				f := &wire.MaxDataFrame{MaximumData: 0x42}
				add(&ackhandler.Frame{Frame: f})
				Expect(hasData()).To(BeTrue())
				Expect(getFrame(f.Length(version) - 1)).To(BeNil())
				Expect(getFrame(f.Length(version)).Frame).To(Equal(f))
				Expect(hasData()).To(BeFalse())
			})

			It("queues and retrieves a CRYPTO frame", func() {
				f := &wire.CryptoFrame{Data: []byte("foobar")}
				add(&ackhandler.Frame{Frame: f})
				Expect(hasData()).To(BeTrue())
				Expect(getFrame(f.Length(version)).Frame).To(Equal(f))
				Expect(hasData()).To(BeFalse())
			})

			It("returns split CRYPTO frames", func() {
				f := &ackhandler.Frame{Frame: &wire.CryptoFrame{
					Offset: 100,
					Data:   []byte("foobar"),
				}}
				add(f)
				Expect(hasData()).To(BeTrue())
				f1 := getFrame(f.Length(version) - 3)
				Expect(f1).ToNot(BeNil())
				Expect(f1.Frame).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
				Expect(f1.Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("foo")))
				Expect(f1.Frame.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(100)))
				Expect(hasData()).To(BeTrue())
				f2 := getFrame(protocol.MaxByteCount)
				Expect(f2).ToNot(BeNil())
				Expect(f2.Frame).To(BeAssignableToTypeOf(&wire.CryptoFrame{}))
				Expect(f2.Frame.(*wire.CryptoFrame).Data).To(Equal([]byte("bar")))
				Expect(f2.Frame.(*wire.CryptoFrame).Offset).To(Equal(protocol.ByteCount(103)))
				Expect(hasData()).To(BeFalse())
			})

			It("returns other frames when a CRYPTO frame wouldn't fit", func() {
				f := &wire.CryptoFrame{Data: []byte("foobar")}
				add(&ackhandler.Frame{Frame: f})
				add(&ackhandler.Frame{Frame: &wire.PingFrame{}})
				f1 := getFrame(2) // too small for a CRYPTO frame
				Expect(f1).ToNot(BeNil())
				Expect(f1.Frame).To(BeAssignableToTypeOf(&wire.PingFrame{}))
				Expect(hasData()).To(BeTrue())
				f2 := getFrame(protocol.MaxByteCount)
				Expect(f2).ToNot(BeNil())
				Expect(f2.Frame).To(Equal(f))
			})

			It("retrieves both a CRYPTO frame and a control frame", func() {
				cf := &wire.MaxDataFrame{MaximumData: 0x42}
				f := &wire.CryptoFrame{Data: []byte("foobar")}
				add(&ackhandler.Frame{Frame: f})
				add(&ackhandler.Frame{Frame: cf})
				Expect(hasData()).To(BeTrue())
				Expect(getFrame(protocol.MaxByteCount).Frame).To(Equal(f))
				Expect(getFrame(protocol.MaxByteCount).Frame).To(Equal(cf))
				Expect(hasData()).To(BeFalse())
			})

			It(fmt.Sprintf("drops all %s frames", encLevel), func() {
				add(&ackhandler.Frame{Frame: &wire.CryptoFrame{Data: []byte("foobar")}})
				add(&ackhandler.Frame{Frame: &wire.MaxDataFrame{MaximumData: 0x42}})
				q.DropPackets(encLevel)
				Expect(hasData()).To(BeFalse())
				Expect(getFrame(protocol.MaxByteCount)).To(BeNil())
			})
		})
	}

	Context("Application data", func() {
		It("doesn't dequeue anything when it's empty", func() {
			Expect(q.GetAppDataFrame(protocol.MaxByteCount)).To(BeNil())
		})

		It("queues and retrieves a control frame", func() {
			f := &wire.MaxDataFrame{MaximumData: 0x42}
			Expect(q.HasAppData()).To(BeFalse())
			q.AddAppData(&ackhandler.Frame{Frame: f})
			Expect(q.HasAppData()).To(BeTrue())
			Expect(q.GetAppDataFrame(f.Length(version) - 1)).To(BeNil())
			Expect(q.GetAppDataFrame(f.Length(version)).Frame).To(Equal(f))
			Expect(q.HasAppData()).To(BeFalse())
		})
	})
})
