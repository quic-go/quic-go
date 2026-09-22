package quic

import (
	"fmt"
	"slices"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type newConnID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

type connIDManager struct {
	queue []newConnID

	highestProbingID uint64
	pathMx           sync.Mutex
	pathProbing      map[pathID]newConnID // initialized lazily

	// The connection ID the server sent alongside its preferred address.
	// It belongs to that path, so it is held apart from the queue until the path
	// is taken into use. See AddFromPreferredAddress.
	preferredAddressConnID *newConnID
	// Whether the reserved connection ID's stateless reset token has been
	// registered. That happens when the ID first goes on the wire - the first
	// probe - not when the reservation is made and not only at the move.
	preferredAddressTokenAdded bool

	handshakeComplete         bool
	activeSequenceNumber      uint64
	highestRetired            uint64
	activeConnectionID        protocol.ConnectionID
	activeStatelessResetToken *protocol.StatelessResetToken

	// We change the connection ID after sending on average
	// protocol.PacketsPerConnectionID packets. The actual value is randomized
	// hide the packet loss rate from on-path observers.
	rand                   utils.Rand
	packetsSinceLastChange uint32
	packetsPerConnectionID uint32

	addStatelessResetToken    func(protocol.StatelessResetToken)
	removeStatelessResetToken func(protocol.StatelessResetToken)
	queueControlFrame         func(wire.Frame)

	closed bool
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID,
	addStatelessResetToken func(protocol.StatelessResetToken),
	removeStatelessResetToken func(protocol.StatelessResetToken),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		activeConnectionID:        initialDestConnID,
		addStatelessResetToken:    addStatelessResetToken,
		removeStatelessResetToken: removeStatelessResetToken,
		queueControlFrame:         queueControlFrame,
		queue:                     make([]newConnID, 0, protocol.MaxActiveConnectionIDs),
	}
}

// AddFromPreferredAddress reserves the connection ID that the server sent
// alongside its preferred address.
//
// The ID is not queued for general use. It belongs to the preferred-address
// path, and it always occupies sequence number 1 (RFC 9000, section 5.1.1),
// which is also the first sequence number the server's own NEW_CONNECTION_ID
// frames take. Letting both reach the queue reports conflicting connection IDs
// and kills the connection.
//
// Its stateless reset token is deliberately not registered here. An endpoint
// must not look for reset tokens belonging to connection IDs it hasn't used
// (RFC 9000, section 10.3.1); the token is registered when the ID first goes on
// the wire, by RegisterPreferredAddressResetToken.
func (h *connIDManager) AddFromPreferredAddress(connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) {
	h.assertNotClosed()
	h.preferredAddressConnID = &newConnID{
		SequenceNumber:      1,
		ConnectionID:        connID,
		StatelessResetToken: resetToken,
	}
}

// RegisterPreferredAddressResetToken starts recognizing the stateless reset
// token that came with the reserved connection ID. It is called when the first
// probe carrying that ID is sent: the ID is in use from that moment, which is
// exactly when the ordinary path-probing machinery registers its tokens, and
// the description ties the token to the connection ID rather than to the move.
func (h *connIDManager) RegisterPreferredAddressResetToken() {
	if h.preferredAddressConnID == nil || h.preferredAddressTokenAdded {
		return
	}
	h.preferredAddressTokenAdded = true
	h.addStatelessResetToken(h.preferredAddressConnID.StatelessResetToken)
}

// PreferredAddressConnID returns the connection ID reserved for the preferred
// address. It reports false once that ID has been retired or taken into use,
// which is what stops a retired connection ID from being put back on the wire
// by a retransmitted probe.
func (h *connIDManager) PreferredAddressConnID() (protocol.ConnectionID, bool) {
	h.assertNotClosed()
	if h.preferredAddressConnID == nil {
		return protocol.ConnectionID{}, false
	}
	return h.preferredAddressConnID.ConnectionID, true
}

// UsePreferredAddressConnID makes the reserved connection ID the active one and
// retires the ID the connection was using until now. This mirrors
// updateConnectionID, which does the same for an ordinary rotation.
func (h *connIDManager) UsePreferredAddressConnID() bool {
	h.assertNotClosed()
	entry := h.preferredAddressConnID
	if entry == nil {
		return false
	}
	h.preferredAddressConnID = nil

	h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: h.activeSequenceNumber})
	// highestRetired is read by add() as "every sequence strictly below this is
	// dead". The rotation we are undoing retired every sequence up to and
	// including the old active one (sequence 1 excepted, and that is the one
	// becoming active), so record the boundary as one past it. Recording the
	// exact number instead would let a duplicate of the old active sequence back
	// into the queue after the move.
	h.highestRetired = max(h.highestRetired, h.activeSequenceNumber+1)
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
	h.activeSequenceNumber = entry.SequenceNumber
	h.activeConnectionID = entry.ConnectionID
	h.activeStatelessResetToken = &entry.StatelessResetToken
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + uint32(h.rand.Int31n(protocol.PacketsPerConnectionID))
	if !h.preferredAddressTokenAdded {
		h.preferredAddressTokenAdded = true
		h.addStatelessResetToken(entry.StatelessResetToken)
	}
	return true
}

// RetirePreferredAddressConnID hands the reserved connection ID back when the
// preferred address will not be used after all. Nothing needs to be
// unregistered: the ID was never used, so its reset token was never registered.
func (h *connIDManager) RetirePreferredAddressConnID() {
	if h.closed || h.preferredAddressConnID == nil {
		return
	}
	entry := h.preferredAddressConnID
	h.preferredAddressConnID = nil
	// A probe may already have put the ID on the wire and registered its token;
	// a retired ID's token stops being recognized with it.
	if h.preferredAddressTokenAdded {
		h.preferredAddressTokenAdded = false
		h.removeStatelessResetToken(entry.StatelessResetToken)
	}
	h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
	// One past the retired sequence, for the same reason as in
	// UsePreferredAddressConnID: a reissue of the abandoned sequence number must
	// read as retired, not as an ordinary addition.
	h.highestRetired = max(h.highestRetired, entry.SequenceNumber+1)
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if err := h.add(f); err != nil {
		return err
	}
	// The reserved preferred-address ID is one of the connection IDs we are
	// storing, so it counts against the limit we advertised even though it is
	// held outside the queue (see conn_id_generator.go, which says the limit
	// includes the ID in preferred_address).
	stored := len(h.queue)
	if h.preferredAddressConnID != nil {
		stored++
	}
	if stored >= protocol.MaxActiveConnectionIDs {
		return &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}
	}
	return nil
}

func (h *connIDManager) add(f *wire.NewConnectionIDFrame) error {
	if h.activeConnectionID.Len() == 0 {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_CONNECTION_ID frame but zero-length connection IDs are in use",
		}
	}
	// The connection ID reserved for the preferred address sits outside the
	// queue, so it needs its own conflict check: the server must not hand out
	// sequence number 1 a second time. This has to come BEFORE the reordering
	// shortcut below. Once an ordinary rotation has moved the active sequence
	// past 1, a repeat of the reserved frame looks stale, and retiring it would
	// tell the server we had given up the very connection ID the preferred path
	// is about to move with.
	// A duplicate of the reservation is tolerated, but not returned from early:
	// the frame may still carry a RetirePriorTo directive, and dropping that
	// would leave the client using a connection ID the peer has retired. The
	// flag routes the frame past the checks below that do not apply to it.
	var reservedDuplicate bool
	if h.preferredAddressConnID != nil && f.SequenceNumber == h.preferredAddressConnID.SequenceNumber {
		if f.ConnectionID != h.preferredAddressConnID.ConnectionID {
			return fmt.Errorf("received conflicting connection IDs for sequence number %d", f.SequenceNumber)
		}
		if f.StatelessResetToken != h.preferredAddressConnID.StatelessResetToken {
			return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", f.SequenceNumber)
		}
		reservedDuplicate = true
	}

	// The reservation's retirement, also before the reordering shortcut. The
	// ordinary manager assumes sequence numbers only advance, but a preferred
	// address deliberately holds sequence 1 while old-path traffic rotates past
	// it. A delayed frame whose own sequence looks stale can still carry a
	// RetirePriorTo that retires the reservation, and taking the shortcut first
	// would drop that retirement and let the move happen with a connection ID
	// the server has taken back (RFC 9000, section 5.1.2).
	if h.preferredAddressConnID != nil && h.preferredAddressConnID.SequenceNumber < f.RetirePriorTo {
		entry := h.preferredAddressConnID
		h.preferredAddressConnID = nil
		// A probe may already have registered the token. It goes with the
		// connection ID it belongs to - leaving it behind would keep routing
		// reset-shaped packets for a retired ID to this connection for the
		// transport's lifetime.
		if h.preferredAddressTokenAdded {
			h.preferredAddressTokenAdded = false
			h.removeStatelessResetToken(entry.StatelessResetToken)
		}
		h.queueControlFrame(&wire.RetireConnectionIDFrame{
			SequenceNumber: entry.SequenceNumber,
		})
	}

	// If the NEW_CONNECTION_ID frame is reordered, such that its sequence number is smaller than the currently active
	// connection ID or if it was already retired, send the RETIRE_CONNECTION_ID frame immediately.
	// The active sequence itself is exempt from the retired-set clause: after the
	// preferred-address move the active sequence steps back to 1 while
	// highestRetired stays above it, and a network duplicate of the active
	// connection ID is a repeat to tolerate, not a stale frame - retiring it
	// would tell the server we had given up the connection ID in use on the new
	// path. In ordinary operation the active sequence never trails highestRetired,
	// so this exemption changes nothing there.
	staleByRetired := f.SequenceNumber < h.highestRetired && f.SequenceNumber != h.activeSequenceNumber
	// The probing clause needs the same exemption: after the move the active
	// sequence is 1, and a path probe taken through the public API pushes
	// highestProbingID above it, so without this a duplicate of the active
	// frame would satisfy the max() and retire the connection ID in use.
	staleBySequence := f.SequenceNumber < max(h.activeSequenceNumber, h.highestProbingID) && f.SequenceNumber != h.activeSequenceNumber
	if !reservedDuplicate && (staleBySequence || staleByRetired) {
		h.queueControlFrame(&wire.RetireConnectionIDFrame{
			SequenceNumber: f.SequenceNumber,
		})
		return nil
	}

	if f.RetirePriorTo != 0 && h.pathProbing != nil {
		for id, entry := range h.pathProbing {
			if entry.SequenceNumber < f.RetirePriorTo {
				h.queueControlFrame(&wire.RetireConnectionIDFrame{
					SequenceNumber: entry.SequenceNumber,
				})
				h.removeStatelessResetToken(entry.StatelessResetToken)
				delete(h.pathProbing, id)
			}
		}
	}
	// Retire elements in the queue.
	// Doesn't retire the active connection ID.
	if f.RetirePriorTo > h.highestRetired {
		var newQueue []newConnID
		for _, entry := range h.queue {
			if entry.SequenceNumber >= f.RetirePriorTo {
				newQueue = append(newQueue, entry)
			} else {
				h.queueControlFrame(&wire.RetireConnectionIDFrame{SequenceNumber: entry.SequenceNumber})
			}
		}
		h.queue = newQueue
		h.highestRetired = f.RetirePriorTo
	}

	if f.SequenceNumber == h.activeSequenceNumber {
		return nil
	}

	if !reservedDuplicate {
		if err := h.addConnectionID(f.SequenceNumber, f.ConnectionID, f.StatelessResetToken); err != nil {
			return err
		}
	}

	// Retire the active connection ID, if necessary.
	// For an ordinary frame the queue is guaranteed non-empty here, because the
	// frame itself was just added. A duplicate of the reservation added nothing,
	// and with nothing left to rotate onto the active ID stays where it is: the
	// reserved ID belongs to the new path and is not a substitute.
	if h.activeSequenceNumber < f.RetirePriorTo && len(h.queue) > 0 {
		h.updateConnectionID()
	}
	return nil
}

func (h *connIDManager) addConnectionID(seq uint64, connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	// fast path: add to the end of the queue
	if len(h.queue) == 0 || h.queue[len(h.queue)-1].SequenceNumber < seq {
		h.queue = append(h.queue, newConnID{
			SequenceNumber:      seq,
			ConnectionID:        connID,
			StatelessResetToken: resetToken,
		})
		return nil
	}

	// slow path: insert in the middle
	for i, entry := range h.queue {
		if entry.SequenceNumber == seq {
			if entry.ConnectionID != connID {
				return fmt.Errorf("received conflicting connection IDs for sequence number %d", seq)
			}
			if entry.StatelessResetToken != resetToken {
				return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", seq)
			}
			return nil
		}

		// insert at the correct position to maintain sorted order
		if entry.SequenceNumber > seq {
			h.queue = slices.Insert(h.queue, i, newConnID{
				SequenceNumber:      seq,
				ConnectionID:        connID,
				StatelessResetToken: resetToken,
			})
			return nil
		}
	}
	return nil // unreachable
}

func (h *connIDManager) updateConnectionID() {
	h.assertNotClosed()
	h.queueControlFrame(&wire.RetireConnectionIDFrame{
		SequenceNumber: h.activeSequenceNumber,
	})
	h.highestRetired = max(h.highestRetired, h.activeSequenceNumber)
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}

	front := h.queue[0]
	h.queue = h.queue[1:]
	h.activeSequenceNumber = front.SequenceNumber
	h.activeConnectionID = front.ConnectionID
	h.activeStatelessResetToken = &front.StatelessResetToken
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + uint32(h.rand.Int31n(protocol.PacketsPerConnectionID))
	h.addStatelessResetToken(*h.activeStatelessResetToken)
}

func (h *connIDManager) Close() {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.closed = true
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
	for _, entry := range h.pathProbing {
		h.removeStatelessResetToken(entry.StatelessResetToken)
	}
	clear(h.pathProbing)
	// An in-flight preferred-address probe registered its token too; once it
	// becomes active the loop above covers it, but until then it has to be
	// removed here or the transport retains the closed connection.
	if h.preferredAddressTokenAdded && h.preferredAddressConnID != nil {
		h.removeStatelessResetToken(h.preferredAddressConnID.StatelessResetToken)
	}
}

// is called when the server performs a Retry
// and when the server changes the connection ID in the first Initial sent
func (h *connIDManager) ChangeInitialConnID(newConnID protocol.ConnectionID) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeConnectionID = newConnID
}

// is called when the server provides a stateless reset token in the transport parameters
func (h *connIDManager) SetStatelessResetToken(token protocol.StatelessResetToken) {
	h.assertNotClosed()
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeStatelessResetToken = &token
	h.addStatelessResetToken(token)
}

func (h *connIDManager) SentPacket() {
	h.packetsSinceLastChange++
}

func (h *connIDManager) shouldUpdateConnID() bool {
	if !h.handshakeComplete {
		return false
	}
	// initiate the first change as early as possible (after handshake completion)
	if len(h.queue) > 0 && h.activeSequenceNumber == 0 {
		return true
	}
	// For later changes, only change if
	// 1. The queue of connection IDs is filled more than 50%.
	// 2. We sent at least PacketsPerConnectionID packets
	return 2*len(h.queue) >= protocol.MaxActiveConnectionIDs &&
		h.packetsSinceLastChange >= h.packetsPerConnectionID
}

func (h *connIDManager) Get() protocol.ConnectionID {
	h.assertNotClosed()
	if h.shouldUpdateConnID() {
		h.updateConnectionID()
	}
	return h.activeConnectionID
}

func (h *connIDManager) SetHandshakeComplete() {
	h.handshakeComplete = true
}

// GetConnIDForPath retrieves a connection ID for a new path (i.e. not the active one).
// Once a connection ID is allocated for a path, it cannot be used for a different path.
// When called with the same pathID, it will return the same connection ID,
// unless the peer requested that this connection ID be retired.
func (h *connIDManager) GetConnIDForPath(id pathID) (protocol.ConnectionID, bool) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	h.assertNotClosed()
	// if we're using zero-length connection IDs, we don't need to change the connection ID
	if h.activeConnectionID.Len() == 0 {
		return protocol.ConnectionID{}, true
	}

	if h.pathProbing == nil {
		h.pathProbing = make(map[pathID]newConnID)
	}
	entry, ok := h.pathProbing[id]
	if ok {
		return entry.ConnectionID, true
	}
	if len(h.queue) == 0 {
		return protocol.ConnectionID{}, false
	}
	front := h.queue[0]
	h.queue = h.queue[1:]
	h.pathProbing[id] = front
	h.highestProbingID = front.SequenceNumber
	h.addStatelessResetToken(front.StatelessResetToken)
	return front.ConnectionID, true
}

func (h *connIDManager) RetireConnIDForPath(pathID pathID) {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	entry, ok := h.pathProbing[pathID]
	if !ok {
		return
	}
	h.queueControlFrame(&wire.RetireConnectionIDFrame{
		SequenceNumber: entry.SequenceNumber,
	})
	h.removeStatelessResetToken(entry.StatelessResetToken)
	delete(h.pathProbing, pathID)
}

func (h *connIDManager) IsActiveStatelessResetToken(token protocol.StatelessResetToken) bool {
	h.pathMx.Lock()
	defer h.pathMx.Unlock()

	if h.activeStatelessResetToken != nil {
		if *h.activeStatelessResetToken == token {
			return true
		}
	}
	if h.pathProbing != nil {
		for _, entry := range h.pathProbing {
			if entry.StatelessResetToken == token {
				return true
			}
		}
	}
	// The reserved preferred-address ID is being probed too, once its token has
	// been registered - the same recognition the entries above get.
	if h.preferredAddressTokenAdded && h.preferredAddressConnID != nil &&
		h.preferredAddressConnID.StatelessResetToken == token {
		return true
	}
	return false
}

// Using the connIDManager after it has been closed can have disastrous effects:
// If the connection ID is rotated, a new entry would be inserted into the packet handler map,
// leading to a memory leak of the connection struct.
// See https://github.com/quic-go/quic-go/pull/4852 for more details.
func (h *connIDManager) assertNotClosed() {
	if h.closed {
		panic("connection ID manager is closed")
	}
}
