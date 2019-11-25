package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID Manager", func() {
	var (
		m             *connIDManager
		frameQueue    []wire.Frame
		tokenAdded    *[16]byte
		retiredTokens [][16]byte
		removedTokens [][16]byte
	)
	initialConnID := protocol.ConnectionID{0, 0, 0, 0}

	BeforeEach(func() {
		frameQueue = nil
		tokenAdded = nil
		retiredTokens = nil
		removedTokens = nil
		m = newConnIDManager(
			initialConnID,
			func(token [16]byte) { tokenAdded = &token },
			func(token [16]byte) { removedTokens = append(removedTokens, token) },
			func(token [16]byte) { retiredTokens = append(retiredTokens, token) },
			func(f wire.Frame,
			) {
				frameQueue = append(frameQueue, f)
			})
	})

	get := func() (protocol.ConnectionID, *[16]byte) {
		if m.queue.Len() == 0 {
			return nil, nil
		}
		val := m.queue.Remove(m.queue.Front())
		return val.ConnectionID, val.StatelessResetToken
	}

	It("returns the initial connection ID", func() {
		Expect(m.Get()).To(Equal(initialConnID))
	})

	It("changes the initial connection ID", func() {
		m.ChangeInitialConnID(protocol.ConnectionID{1, 2, 3, 4, 5})
		Expect(m.Get()).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5}))
	})

	It("sets the token for the first connection ID", func() {
		token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		m.SetStatelessResetToken(token)
		Expect(*m.activeStatelessResetToken).To(Equal(token))
		Expect(*tokenAdded).To(Equal(token))
	})

	It("adds and gets connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      10,
			ConnectionID:        protocol.ConnectionID{2, 3, 4, 5},
			StatelessResetToken: [16]byte{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      4,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		})).To(Succeed())
		c1, rt1 := get()
		Expect(c1).To(Equal(protocol.ConnectionID{1, 2, 3, 4}))
		Expect(*rt1).To(Equal([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe}))
		c2, rt2 := get()
		Expect(c2).To(Equal(protocol.ConnectionID{2, 3, 4, 5}))
		Expect(*rt2).To(Equal([16]byte{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}))
		c3, rt3 := get()
		Expect(c3).To(BeNil())
		Expect(rt3).To(BeNil())
	})

	It("accepts duplicates", func() {
		f := &wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		}
		Expect(m.Add(f)).To(Succeed())
		Expect(m.Add(f)).To(Succeed())
		c1, rt1 := get()
		Expect(c1).To(Equal(protocol.ConnectionID{1, 2, 3, 4}))
		Expect(*rt1).To(Equal([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe}))
		c2, rt2 := get()
		Expect(c2).To(BeNil())
		Expect(rt2).To(BeNil())
	})

	It("ignores duplicates for the currently used connection ID", func() {
		f := &wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		}
		Expect(m.Add(f)).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ConnectionID{1, 2, 3, 4}))
		c, _ := get()
		Expect(c).To(BeNil())
		// Now send the same connection ID again. It should not be queued.
		Expect(m.Add(f)).To(Succeed())
		c, _ = get()
		Expect(c).To(BeNil())
	})

	It("rejects duplicates with different connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 42,
			ConnectionID:   protocol.ConnectionID{1, 2, 3, 4},
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 42,
			ConnectionID:   protocol.ConnectionID{2, 3, 4, 5},
		})).To(MatchError("received conflicting connection IDs for sequence number 42"))
	})

	It("rejects duplicates with different connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      42,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe},
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      42,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		})).To(MatchError("received conflicting stateless reset tokens for sequence number 42"))
	})

	It("retires connection IDs", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 10,
			ConnectionID:   protocol.ConnectionID{1, 2, 3, 4},
		})).To(Succeed())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 13,
			ConnectionID:   protocol.ConnectionID{2, 3, 4, 5},
		})).To(Succeed())
		Expect(frameQueue).To(BeEmpty())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			RetirePriorTo:  14,
			SequenceNumber: 17,
			ConnectionID:   protocol.ConnectionID{3, 4, 5, 6},
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(3))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(10))
		Expect(frameQueue[1].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(13))
		Expect(frameQueue[2].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		Expect(m.Get()).To(Equal(protocol.ConnectionID{3, 4, 5, 6}))
	})

	It("ignores reordered connection IDs, if their sequence number was already retired", func() {
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 10,
			ConnectionID:   protocol.ConnectionID{1, 2, 3, 4},
			RetirePriorTo:  5,
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		frameQueue = nil
		// If this NEW_CONNECTION_ID frame hadn't been reordered, we would have retired it before.
		// Make sure it gets retired immediately now.
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 4,
			ConnectionID:   protocol.ConnectionID{4, 3, 2, 1},
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(4))
	})

	It("retires old connection IDs when the peer sends too many new ones", func() {
		for i := uint8(1); i <= protocol.MaxActiveConnectionIDs; i++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(i),
				ConnectionID:        protocol.ConnectionID{i, i, i, i},
				StatelessResetToken: [16]byte{i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i},
			})).To(Succeed())
		}
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeZero())
		Expect(retiredTokens).To(BeEmpty())
		frameQueue = nil
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: protocol.MaxActiveConnectionIDs + 1,
			ConnectionID:   protocol.ConnectionID{1, 2, 3, 4},
		})).To(Succeed())
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(1))
		Expect(retiredTokens).To(HaveLen(1))
		Expect(retiredTokens[0]).To(Equal([16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
	})

	It("initiates the first connection ID update as soon as possible", func() {
		Expect(m.Get()).To(Equal(initialConnID))
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		})).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ConnectionID{1, 2, 3, 4}))

	})

	It("initiates subsequent updates when enough packets are sent", func() {
		var s uint8
		for s = uint8(1); s <= protocol.MaxActiveConnectionIDs; s++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(s),
				ConnectionID:        protocol.ConnectionID{s, s, s, s},
				StatelessResetToken: [16]byte{s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s},
			})).To(Succeed())
		}

		lastConnID := m.Get()
		Expect(lastConnID).To(Equal(protocol.ConnectionID{1, 1, 1, 1}))

		var counter int
		for i := 0; i < 50*protocol.PacketsPerConnectionID; i++ {
			m.SentPacket()

			connID := m.Get()
			if !connID.Equal(lastConnID) {
				counter++
				lastConnID = connID
				Expect(retiredTokens).To(HaveLen(1))
				retiredTokens = nil
				Expect(m.Add(&wire.NewConnectionIDFrame{
					SequenceNumber:      uint64(s),
					ConnectionID:        protocol.ConnectionID{s, s, s, s},
					StatelessResetToken: [16]byte{s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s},
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
				ConnectionID:        protocol.ConnectionID{s, s, s, s},
				StatelessResetToken: [16]byte{s, s, s, s, s, s, s, s, s, s, s, s, s, s, s, s},
			})).To(Succeed())
		}
		Expect(m.Get()).To(Equal(protocol.ConnectionID{10, 10, 10, 10}))
		for {
			m.SentPacket()
			if m.Get().Equal(protocol.ConnectionID{11, 11, 11, 11}) {
				break
			}
		}
		// The active conn ID is now {11, 11, 11, 11}
		Expect(m.queue.Front().Value.ConnectionID).To(Equal(protocol.ConnectionID{12, 12, 12, 12}))
		// Add a delayed connection ID. It should just be ignored now.
		frameQueue = nil
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      uint64(5),
			ConnectionID:        protocol.ConnectionID{5, 5, 5, 5},
			StatelessResetToken: [16]byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
		})).To(Succeed())
		Expect(m.queue.Front().Value.ConnectionID).To(Equal(protocol.ConnectionID{12, 12, 12, 12}))
		Expect(frameQueue).To(HaveLen(1))
		Expect(frameQueue[0].(*wire.RetireConnectionIDFrame).SequenceNumber).To(BeEquivalentTo(5))
	})

	It("only initiates subsequent updates when enough if enough connection IDs are queued", func() {
		for i := uint8(1); i <= protocol.MaxActiveConnectionIDs/2; i++ {
			Expect(m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber:      uint64(i),
				ConnectionID:        protocol.ConnectionID{i, i, i, i},
				StatelessResetToken: [16]byte{i, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i},
			})).To(Succeed())
		}
		Expect(m.Get()).To(Equal(protocol.ConnectionID{1, 1, 1, 1}))
		for i := 0; i < 2*protocol.PacketsPerConnectionID; i++ {
			m.SentPacket()
		}
		Expect(m.Get()).To(Equal(protocol.ConnectionID{1, 1, 1, 1}))
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber: 1337,
			ConnectionID:   protocol.ConnectionID{1, 3, 3, 7},
		})).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ConnectionID{2, 2, 2, 2}))
		Expect(retiredTokens).To(HaveLen(1))
		Expect(retiredTokens[0]).To(Equal([16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}))
	})

	It("removes the currently active stateless reset token when it is closed", func() {
		m.Close()
		Expect(retiredTokens).To(BeEmpty())
		Expect(removedTokens).To(BeEmpty())
		Expect(m.Add(&wire.NewConnectionIDFrame{
			SequenceNumber:      1,
			ConnectionID:        protocol.ConnectionID{1, 2, 3, 4},
			StatelessResetToken: [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		})).To(Succeed())
		Expect(m.Get()).To(Equal(protocol.ConnectionID{1, 2, 3, 4}))
		m.Close()
		Expect(retiredTokens).To(BeEmpty())
		Expect(removedTokens).To(HaveLen(1))
		Expect(removedTokens[0]).To(Equal([16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}))
	})
})
