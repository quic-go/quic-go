package quic

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID Manager", func() {
	var (
		m             *connIDManager
		frameQueue    []wire.Frame
		tokenAdded    *protocol.StatelessResetToken
		removedTokens []protocol.StatelessResetToken
	)
	initialConnID := protocol.ParseConnectionID([]byte{0, 0, 0, 0})

	BeforeEach(func() {
		frameQueue = nil
		tokenAdded = nil
		removedTokens = nil
		m = newConnIDManager(
			initialConnID,
			func(token protocol.StatelessResetToken) { tokenAdded = &token },
			func(token protocol.StatelessResetToken) { removedTokens = append(removedTokens, token) },
			func(f wire.Frame,
			) {
				frameQueue = append(frameQueue, f)
			})
	})

	get := func() (protocol.ConnectionID, protocol.StatelessResetToken) {
		if m.queue.Len() == 0 {
			return protocol.ConnectionID{}, protocol.StatelessResetToken{}
		}
		val := m.queue.Remove(m.queue.Front())
		return val.ConnectionID, val.StatelessResetToken
	}

	It("returns the initial connection ID", func() {
		Expect(m.Get()).To(Equal(initialConnID))
	})

	It("changes the initial connection ID", func() {
		m.ChangeInitialConnID(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5}))
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5})))
	})

	It("sets the token for the first connection ID", func() {
		token := protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		m.SetStatelessResetToken(token)
		Expect(*m.activeStatelessResetToken).To(Equal(token))
		Expect(*tokenAdded).To(Equal(token))
	})

	It("adds and gets connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      10,
			ConnectionID:        protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
			StatelessResetToken: protocol.StatelessResetToken{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      4,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		})).To(Succeed())
		c1, rt1 := get()
		Expect(c1).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
		Expect(rt1).To(Equal(protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe}))
		c2, rt2 := get()
		Expect(c2).To(Equal(protocol.ParseConnectionID([]byte{2, 3, 4, 5})))
		Expect(rt2).To(Equal(protocol.StatelessResetToken{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}))
		c3, _ := get()
		Expect(c3).To(BeZero())
	})

	It("accepts duplicates", func() {
		f1 := &wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		}
		f2 := &wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		}
		Expect(m.Add(f1)).To(Succeed())
		Expect(m.Add(f2)).To(Succeed())
		c1, rt1 := get()
		Expect(c1).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
		Expect(rt1).To(Equal(protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe}))
		c2, _ := get()
		Expect(c2).To(BeZero())
	})

	It("ignores duplicates for the currently used connection ID", func() {
		f := &wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		}
		m.SetHandshakeComplete()
		Expect(m.Add(f)).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
		c, _ := get()
		Expect(c).To(BeZero())
		// Now send the same connection ID again. It should not be queued.
		Expect(m.Add(f)).To(Succeed())
		c, _ = get()
		Expect(c).To(BeZero())
	})

	It("rejects duplicates with different connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 42,
			ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 42,
			ConnectionID:   protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
		})).To(MatchError("received conflicting connection IDs for sequence number 42"))
	})

	It("rejects duplicates with different connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      42,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      42,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		})).To(MatchError("received conflicting stateless reset tokens for sequence number 42"))
	})

	It("retires connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 10,
			ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 13,
			ConnectionID:   protocol.ParseConnectionID([]byte{2, 3, 4, 5}),
		})).To(Succeed())
		Expect(frameQueue).To(BeEmpty())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			RetirePriorTo:  14,
			SequenceNumber: 17,
			ConnectionID:   protocol.ParseConnectionID([]byte{3, 4, 5, 6}),
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(3))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(10))
		Expect(frameQueue[1].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(13))
		Expect(frameQueue[2].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{3, 4, 5, 6})))
	})

	It("ignores reordered connection IDs, if their sequence number was already retired", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 10,
			ConnectionID:   protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			RetirePriorTo:  5,
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		frameQueue = nil
		// If this NEW_CONNECTION_ID frame hadn't been reordered, we would have retired it before.
		// Make sure it gets retired immediately now.
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 4,
			ConnectionID:   protocol.ParseConnectionID([]byte{4, 3, 2, 1}),
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(4))
	})

	It("ignores reordered connection IDs, if their sequence number was already retired or less than active", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 10,
			ConnectionID:   protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			RetirePriorTo:  5,
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		frameQueue = nil
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})))

		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 9,
			ConnectionID:   protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
			RetirePriorTo:  5,
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(9))
	})

	It("accepts retransmissions for the connection ID that is in use", func() {
		connID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})

		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 1,
			ConnectionID:   connID,
		})).To(Succeed())
		m.SetHandshakeComplete()
		Expect(frameQueue).To(BeEmpty())
		Expect(m.Get()).To(Equal(connID))
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0]).To(BeAssignableToTypeOf(&wire.RetireConnectionIDFrame{}))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		frameQueue = nil

		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 1,
			ConnectionID:   connID,
		})).To(Succeed())
		Expect(frameQueue).To(BeEmpty())
	})

	It("errors when the peer sends too connection IDs", func() {
		for i := uint8(1); i < protocol.MaxActiveConnectionIDs; i++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(i),
				ConnectionID:        protocol.ParseConnectionID([]byte{i, i, i, i}),
				StatelessResetToken: protocol.StatelessResetToken{i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i},
			})).To(Succeed())
		}
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(9999),
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		})).To(MatchError(&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}))
	})

	It("initiates the first connection ID update as soon as possible", func() {
		Expect(m.Get()).To(Equal(initialConnID))
		m.SetHandshakeComplete()
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		})).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	})

	It("waits until handshake completion before initiating a connection ID update", func() {
		Expect(m.Get()).To(Equal(initialConnID))
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		})).To(Succeed())
		Expect(m.Get()).To(Equal(initialConnID))
		m.SetHandshakeComplete()
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
	})

	It("initiates subsequent updates when enough packets are sent", func() {
		var s uint8
		for s = uint8(1); s < protocol.MaxActiveConnectionIDs; s++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(s),
				ConnectionID:        protocol.ParseConnectionID([]byte{s, s, s, s}),
				StatelessResetToken: protocol.StatelessResetToken{s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s},
			})).To(Succeed())
		}

		m.SetHandshakeComplete()
		lastConnID := m.Get()
		Expect(lastConnID).To(Equal(protocol.ParseConnectionID([]byte{1, 1, 1, 1})))

		var counter int
		for i := 0; i < 50*protocol.PacketsPerConnectionID; i++ {
			m.SentPacket()

			connID := m.Get()
			if connID != lastConnID {
				counter++
				lastConnID = connID
				Expect(removedTokens).To(HaveLen(1))
				removedTokens = nil
				Expect(m.Add(&wire.NewConnectionIDFrame{
					SequenceNumber:      uint64(s),
					ConnectionID:        protocol.ParseConnectionID([]byte{s, s, s, s}),
					StatelessResetToken: protocol.StatelessResetToken{s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s},
				})).To(Succeed())
				s++
			}
		}
		Expect(counter).To(BeNumerically("~", 50, 10))
	})

	It("retires delayed connection IDs that arrive after a higher connection ID was already retired", func() {
		for s := uint8(10); s <= 10+protocol.MaxActiveConnectionIDs/2; s++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(s),
				ConnectionID:        protocol.ParseConnectionID([]byte{s, s, s, s}),
				StatelessResetToken: protocol.StatelessResetToken{s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s},
			})).To(Succeed())
		}
		m.SetHandshakeComplete()
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{10, 10, 10, 10})))
		for {
			m.SentPacket()
			if m.Get() == protocol.ParseConnectionID([]byte{11, 11, 11, 11}) {
				break
			}
		}
		// The active conn ID is now {11, 11, 11, 11}
		Expect(m.queue.Front().Value.ConnectionID).To(Equal(protocol.ParseConnectionID([]byte{12, 12, 12, 12})))
		// Add a delayed connection ID. It should just be ignored now.
		frameQueue = nil
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(5),
			ConnectionID:        protocol.ParseConnectionID([]byte{5, 5, 5, 5}),
			StatelessResetToken: protocol.StatelessResetToken{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		})).To(Succeed())
		Expect(m.queue.Front().Value.ConnectionID).To(Equal(protocol.ParseConnectionID([]byte{12, 12, 12, 12})))
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(5))
	})

	It("only initiates subsequent updates when enough if enough connection IDs are queued", func() {
		for i := uint8(1); i <= protocol.MaxActiveConnectionIDs/2; i++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(i),
				ConnectionID:        protocol.ParseConnectionID([]byte{i, i, i, i}),
				StatelessResetToken: protocol.StatelessResetToken{i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i},
			})).To(Succeed())
		}
		m.SetHandshakeComplete()
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 1, 1, 1})))
		for i := 0; i < 2*protocol.PacketsPerConnectionID; i++ {
			m.SentPacket()
		}
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 1, 1, 1})))
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 1337,
			ConnectionID:   protocol.ParseConnectionID([]byte{1, 3, 3, 7}),
		})).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{2, 2, 2, 2})))
		Expect(removedTokens).To(HaveLen(1))
		Expect(removedTokens[0]).To(Equal(protocol.StatelessResetToken{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
	})

	It("removes the currently active stateless reset token when it is closed", func() {
		m.Close()
		Expect(removedTokens).To(BeEmpty())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		})).To(Succeed())
		m.SetHandshakeComplete()
		Expect(m.Get()).To(Equal(protocol.ParseConnectionID([]byte{1, 2, 3, 4})))
		m.Close()
		Expect(removedTokens).To(HaveLen(1))
		Expect(removedTokens[0]).To(Equal(protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}))
	})
})
