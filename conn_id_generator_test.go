package quic

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection ID Generator", func() {
	var (
		addedConnIDs       []protocol.ConnectionID
		retiredConnIDs     []protocol.ConnectionID
		removedConnIDs     []protocol.ConnectionID
		replacedWithClosed map[string]packetHandler
		queuedFrames       []wire.Frame
		g                  *connIDGenerator
	)
	initialConnID := protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7}
	initialClientDestConnID := protocol.ConnectionID{0xa, 0xb, 0xc, 0xd, 0xe}

	connIDToToken := func(c protocol.ConnectionID) protocol.StatelessResetToken {
		return protocol.StatelessResetToken{c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0], c[0]}
	}

	BeforeEach(func() {
		addedConnIDs = nil
		retiredConnIDs = nil
		removedConnIDs = nil
		queuedFrames = nil
		replacedWithClosed = make(map[string]packetHandler)
		g = newConnIDGenerator(
			initialConnID,
			initialClientDestConnID,
			func(c protocol.ConnectionID) { addedConnIDs = append(addedConnIDs, c) },
			connIDToToken,
			func(c protocol.ConnectionID) { removedConnIDs = append(removedConnIDs, c) },
			func(c protocol.ConnectionID) { retiredConnIDs = append(retiredConnIDs, c) },
			func(c protocol.ConnectionID, h packetHandler) { replacedWithClosed[string(c)] = h },
			func(f wire.Frame) { queuedFrames = append(queuedFrames, f) },
			protocol.VersionDraft29,
		)
	})

	It("issues new connection IDs", func() {
		Expect(g.SetMaxActiveConnIDs(4)).To(Succeed())
		Expect(retiredConnIDs).To(BeEmpty())
		Expect(addedConnIDs).To(HaveLen(3))
		for i := 0; i < len(addedConnIDs)-1; i++ {
			Expect(addedConnIDs[i]).ToNot(Equal(addedConnIDs[i+1]))
		}
		Expect(queuedFrames).To(HaveLen(3))
		for i := 0; i < 3; i++ {
			f := queuedFrames[i]
			Expect(f).To(BeAssignableToTypeOf(&wire.NewConnectionIDFrame{}))
			nf := f.(*wire.NewConnectionIDFrame)
			Expect(nf.SequenceNumber).To(BeEquivalentTo(i + 1))
			Expect(nf.ConnectionID.Len()).To(Equal(7))
			Expect(nf.StatelessResetToken).To(Equal(connIDToToken(nf.ConnectionID)))
		}
	})

	It("limits the number of connection IDs that it issues", func() {
		Expect(g.SetMaxActiveConnIDs(9999999)).To(Succeed())
		Expect(retiredConnIDs).To(BeEmpty())
		Expect(addedConnIDs).To(HaveLen(protocol.MaxIssuedConnectionIDs - 1))
		Expect(queuedFrames).To(HaveLen(protocol.MaxIssuedConnectionIDs - 1))
	})

	// SetMaxActiveConnIDs is called twice when we dialing a 0-RTT connection:
	// once for the restored from the old connections, once when we receive the transport parameters
	Context("dealing with 0-RTT", func() {
		It("doesn't issue new connection IDs when SetMaxActiveConnIDs is called with the same value", func() {
			Expect(g.SetMaxActiveConnIDs(4)).To(Succeed())
			Expect(queuedFrames).To(HaveLen(3))
			queuedFrames = nil
			Expect(g.SetMaxActiveConnIDs(4)).To(Succeed())
			Expect(queuedFrames).To(BeEmpty())
		})

		It("issues more connection IDs if the server allows a higher limit on the resumed connection", func() {
			Expect(g.SetMaxActiveConnIDs(3)).To(Succeed())
			Expect(queuedFrames).To(HaveLen(2))
			queuedFrames = nil
			Expect(g.SetMaxActiveConnIDs(6)).To(Succeed())
			Expect(queuedFrames).To(HaveLen(3))
		})

		It("issues more connection IDs if the server allows a higher limit on the resumed connection, when connection IDs were retired in between", func() {
			Expect(g.SetMaxActiveConnIDs(3)).To(Succeed())
			Expect(queuedFrames).To(HaveLen(2))
			queuedFrames = nil
			g.Retire(1, protocol.ConnectionID{})
			Expect(queuedFrames).To(HaveLen(1))
			queuedFrames = nil
			Expect(g.SetMaxActiveConnIDs(6)).To(Succeed())
			Expect(queuedFrames).To(HaveLen(3))
		})
	})

	It("errors if the peers tries to retire a connection ID that wasn't yet issued", func() {
		Expect(g.Retire(1, protocol.ConnectionID{})).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "retired connection ID 1 (highest issued: 0)",
		}))
	})

	It("errors if the peers tries to retire a connection ID in a packet with that connection ID", func() {
		Expect(g.SetMaxActiveConnIDs(4)).To(Succeed())
		Expect(queuedFrames).ToNot(BeEmpty())
		Expect(queuedFrames[0]).To(BeAssignableToTypeOf(&wire.NewConnectionIDFrame{}))
		f := queuedFrames[0].(*wire.NewConnectionIDFrame)
		Expect(g.Retire(f.SequenceNumber, f.ConnectionID)).To(MatchError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", f.SequenceNumber, f.ConnectionID),
		}))
	})

	It("issues new connection IDs, when old ones are retired", func() {
		Expect(g.SetMaxActiveConnIDs(5)).To(Succeed())
		queuedFrames = nil
		Expect(retiredConnIDs).To(BeEmpty())
		Expect(g.Retire(3, protocol.ConnectionID{})).To(Succeed())
		Expect(queuedFrames).To(HaveLen(1))
		Expect(queuedFrames[0]).To(BeAssignableToTypeOf(&wire.NewConnectionIDFrame{}))
		nf := queuedFrames[0].(*wire.NewConnectionIDFrame)
		Expect(nf.SequenceNumber).To(BeEquivalentTo(5))
		Expect(nf.ConnectionID.Len()).To(Equal(7))
	})

	It("retires the initial connection ID", func() {
		Expect(g.Retire(0, protocol.ConnectionID{})).To(Succeed())
		Expect(removedConnIDs).To(BeEmpty())
		Expect(retiredConnIDs).To(HaveLen(1))
		Expect(retiredConnIDs[0]).To(Equal(initialConnID))
		Expect(addedConnIDs).To(BeEmpty())
	})

	It("handles duplicate retirements", func() {
		Expect(g.SetMaxActiveConnIDs(11)).To(Succeed())
		queuedFrames = nil
		Expect(retiredConnIDs).To(BeEmpty())
		Expect(g.Retire(5, protocol.ConnectionID{})).To(Succeed())
		Expect(retiredConnIDs).To(HaveLen(1))
		Expect(queuedFrames).To(HaveLen(1))
		Expect(g.Retire(5, protocol.ConnectionID{})).To(Succeed())
		Expect(retiredConnIDs).To(HaveLen(1))
		Expect(queuedFrames).To(HaveLen(1))
	})

	It("retires the client's initial destination connection ID when the handshake completes", func() {
		g.SetHandshakeComplete()
		Expect(retiredConnIDs).To(HaveLen(1))
		Expect(retiredConnIDs[0]).To(Equal(initialClientDestConnID))
	})

	It("removes all connection IDs", func() {
		Expect(g.SetMaxActiveConnIDs(5)).To(Succeed())
		Expect(queuedFrames).To(HaveLen(4))
		g.RemoveAll()
		Expect(removedConnIDs).To(HaveLen(6)) // initial conn ID, initial client dest conn id, and newly issued ones
		Expect(removedConnIDs).To(ContainElement(initialConnID))
		Expect(removedConnIDs).To(ContainElement(initialClientDestConnID))
		for _, f := range queuedFrames {
			nf := f.(*wire.NewConnectionIDFrame)
			Expect(removedConnIDs).To(ContainElement(nf.ConnectionID))
		}
	})

	It("replaces with a closed connection for all connection IDs", func() {
		Expect(g.SetMaxActiveConnIDs(5)).To(Succeed())
		Expect(queuedFrames).To(HaveLen(4))
		sess := NewMockPacketHandler(mockCtrl)
		g.ReplaceWithClosed(sess)
		Expect(replacedWithClosed).To(HaveLen(6)) // initial conn ID, initial client dest conn id, and newly issued ones
		Expect(replacedWithClosed).To(HaveKeyWithValue(string(initialClientDestConnID), sess))
		Expect(replacedWithClosed).To(HaveKeyWithValue(string(initialConnID), sess))
		for _, f := range queuedFrames {
			nf := f.(*wire.NewConnectionIDFrame)
			Expect(replacedWithClosed).To(HaveKeyWithValue(string(nf.ConnectionID), sess))
		}
	})
})
