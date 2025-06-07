package quic

import (
	"fmt"
	"slices"
	"time" // Keep for future use e.g. CID retirement timers

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils" // For logger
	"github.com/quic-go/quic-go/internal/wire"
)

// connIDInfo stores information about a Connection ID provided by the peer.
// These are used as Destination Connection IDs in packets we send.
type connIDInfo struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken // Not a pointer, as it's mandatory in NEW_CONNECTION_ID_FRAME
	PathID              protocol.PathID
}

type connIDManager struct {
	// connIDsByPath stores CIDs provided by the peer, mapped by PathID and then by SequenceNumber.
	connIDsByPath map[protocol.PathID]map[uint64]*connIDInfo
	// activeDestConnIDByPath stores the current active Destination Connection ID for sending on a specific path.
	activeDestConnIDByPath map[protocol.PathID]protocol.ConnectionID
	// activeDestConnIDSeqNumByPath stores the sequence number of the active DCID for each path.
	activeDestConnIDSeqNumByPath map[protocol.PathID]uint64
	// highestRetiredSeqNumByPath stores the highest sequence number of a CID retired by the peer
	// (via RetirePriorTo in PATH_NEW_CONNECTION_ID) for CIDs they issued to us on this path.
	highestRetiredSeqNumByPath map[protocol.PathID]uint64

	// connIDLimitPerPath is our local limit for how many CIDs we are willing to store from the peer per path.
	// This corresponds to our "active_connection_id_limit" transport parameter.
	connIDLimitPerPath uint64
	// getPeerPathLimit is a function to get the peer's advertised MAX_PATH_ID.
	// This tells us the maximum Path ID the peer is willing to receive CIDs for.
	getPeerPathLimitFunc func() protocol.PathID

	// Callbacks to interact with the connection/packet handling
	addResetTokenFunc    func(token protocol.StatelessResetToken) // Add to global list for stateless reset validation
	removeResetTokenFunc func(token protocol.StatelessResetToken) // Remove from global list
	queueControlFrameFunc func(wire.Frame)                         // To queue PATH_RETIRE_CONNECTION_ID frames

	handshakeComplete bool
	closed            bool
	logger            utils.Logger
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID, // Peer's initial SCID (our DCID for Path 0)
	initialSRT *protocol.StatelessResetToken, // Peer's SRT for their initial SCID (if provided in TP)
	connIDLimitPerPath uint64, // Our local `active_connection_id_limit`
	getPeerPathLimitFunc func() protocol.PathID, // Function to get peer's MAX_PATH_ID
	addResetTokenFunc func(protocol.StatelessResetToken),
	removeResetTokenFunc func(protocol.StatelessResetToken),
	queueControlFrameFunc func(wire.Frame),
	logger utils.Logger,
) *connIDManager {
	m := &connIDManager{
		connIDsByPath:                make(map[protocol.PathID]map[uint64]*connIDInfo),
		activeDestConnIDByPath:      make(map[protocol.PathID]protocol.ConnectionID),
		activeDestConnIDSeqNumByPath: make(map[protocol.PathID]uint64),
		highestRetiredSeqNumByPath:   make(map[protocol.PathID]uint64),
		connIDLimitPerPath:           connIDLimitPerPath,
		getPeerPathLimitFunc:         getPeerPathLimitFunc,
		addResetTokenFunc:            addResetTokenFunc,
		removeResetTokenFunc:         removeResetTokenFunc,
		queueControlFrameFunc:        queueControlFrameFunc,
		logger:                       logger,
	}

	// Initialize Path 0
	path0ID := protocol.InitialPathID
	m.connIDsByPath[path0ID] = make(map[uint64]*connIDInfo)

	var srt protocol.StatelessResetToken
	if initialSRT != nil {
		srt = *initialSRT
	} // else it's a zero SRT

	initialCIDInfo := &connIDInfo{
		SequenceNumber:      0, // Initial CIDs have sequence number 0
		ConnectionID:        initialDestConnID,
		StatelessResetToken: srt,
		PathID:              path0ID,
	}
	m.connIDsByPath[path0ID][0] = initialCIDInfo
	m.activeDestConnIDByPath[path0ID] = initialDestConnID
	m.activeDestConnIDSeqNumByPath[path0ID] = 0
	// highestRetired for path 0 is implicitly < 0 initially.
	// No need to set in highestRetiredSeqNumByPath until a RetirePriorTo > 0 is received for path 0.

	if initialSRT != nil { // Only add if it was actually provided
		m.addResetTokenFunc(*initialSRT)
	}
	return m
}

// Add handles a PATH_NEW_CONNECTION_ID frame from the peer.
func (m *connIDManager) Add(frame *wire.PathNewConnectionIDFrame) error {
	m.assertNotClosed()
	pathID := frame.PathIdentifier
	peerMaxPathID := protocol.InitialPathID // Default if func is nil
	if m.getPeerPathLimitFunc != nil {
		peerMaxPathID = m.getPeerPathLimitFunc()
	}

	if pathID > peerMaxPathID && peerMaxPathID != 0 { // Path ID 0 is always allowed
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("received PATH_NEW_CONNECTION_ID for path %d beyond peer's advertised MAX_PATH_ID %d", pathID, peerMaxPathID),
		}
	}

	if _, ok := m.connIDsByPath[pathID]; !ok {
		m.connIDsByPath[pathID] = make(map[uint64]*connIDInfo)
		// highestRetiredSeqNumByPath[pathID] will default to 0, which is fine.
	}

	// Retire CIDs with sequence numbers less than frame.RetirePriorTo for this path
	if frame.RetirePriorTo > 0 {
		currentHighestRetired := m.highestRetiredSeqNumByPath[pathID]
		for seqNum, cidInfo := range m.connIDsByPath[pathID] {
			if seqNum < frame.RetirePriorTo {
				m.removeResetTokenFunc(cidInfo.StatelessResetToken)
				delete(m.connIDsByPath[pathID], seqNum)
				m.logger.Debugf("Retired peer's CID %s (seq %d) on path %d due to RetirePriorTo %d", cidInfo.ConnectionID, seqNum, pathID, frame.RetirePriorTo)
				// If this was the active CID for the path, clear it. A new one will be selected below.
				if activeCID, ok := m.activeDestConnIDByPath[pathID]; ok && activeCID.Equal(cidInfo.ConnectionID) {
					delete(m.activeDestConnIDByPath, pathID)
					delete(m.activeDestConnIDSeqNumByPath, pathID)
				}
			}
		}
		m.highestRetiredSeqNumByPath[pathID] = max(currentHighestRetired, frame.RetirePriorTo)
	}

	// Check if CID already exists or if sequence number is too low
	if existing, ok := m.connIDsByPath[pathID][frame.SequenceNumber]; ok {
		if existing.ConnectionID.Equal(frame.ConnectionID) {
			// If token also matches, it's a duplicate. If not, it's a conflict.
			if existing.StatelessResetToken == frame.StatelessResetToken {
				return nil // Duplicate, ignore
			}
			return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: fmt.Sprintf("conflicting stateless reset token for CID %s seq %d on path %d", frame.ConnectionID, frame.SequenceNumber, pathID)}
		}
		return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: fmt.Sprintf("conflicting CID for sequence number %d on path %d", frame.SequenceNumber, pathID)}
	}

	if frame.SequenceNumber < m.highestRetiredSeqNumByPath[pathID] {
		m.logger.Debugf("Received PATH_NEW_CONNECTION_ID for already retired sequence number %d on path %d", frame.SequenceNumber, pathID)
		// Per RFC9000: "An endpoint that receives a NEW_CONNECTION_ID frame with a sequence number
		// that it has already retired SHOULD send a corresponding RETIRE_CONNECTION_ID frame"
		// This manager handles CIDs from peer, so if peer sends an already retired one, we re-retire *their* CID.
		// This means we tell them we are retiring their CID with that sequence number.
		m.queueControlFrameFunc(&wire.PathRetireConnectionIDFrame{PathIdentifier: pathID, SequenceNumber: frame.SequenceNumber})
		return nil
	}

	// Check connection ID limit for this path
	// Count non-retired CIDs for this path.
	// The limit is on "active" CIDs from peer's perspective, which means CIDs we haven't told them to retire yet.
	// Our m.connIDsByPath[pathID] stores CIDs peer gave us that *we* haven't told them we are retiring.
	if uint64(len(m.connIDsByPath[pathID])) >= m.connIDLimitPerPath {
		return &qerr.TransportError{
			ErrorCode:    qerr.ConnectionIDLimitError,
			ErrorMessage: fmt.Sprintf("exceeded connection ID limit for path %d", pathID),
		}
	}

	newInfo := &connIDInfo{
		SequenceNumber:      frame.SequenceNumber,
		ConnectionID:        frame.ConnectionID,
		StatelessResetToken: frame.StatelessResetToken,
		PathID:              pathID,
	}
	m.connIDsByPath[pathID][frame.SequenceNumber] = newInfo
	m.addResetTokenFunc(frame.StatelessResetToken)

	// If no active CID for path, or if new CID has higher sequence number than current active, make it active.
	// (Or if current active was just retired by RetirePriorTo)
	currentActiveSeqNum, isActiveSet := m.activeDestConnIDSeqNumByPath[pathID]
	if !isActiveSet || frame.SequenceNumber >= currentActiveSeqNum { // Prefer higher sequence numbers
		m.activeDestConnIDByPath[pathID] = newInfo.ConnectionID
		m.activeDestConnIDSeqNumByPath[pathID] = newInfo.SequenceNumber
		m.logger.Debugf("Set active DCID for path %d to %s (seq %d)", pathID, newInfo.ConnectionID, newInfo.SequenceNumber)
	}
	return nil
}

// RetireDestinationConnectionID is called by us when we decide to stop using a CID the peer gave us for a path.
// This will queue a PATH_RETIRE_CONNECTION_ID frame to be sent to the peer.
func (m *connIDManager) RetireDestinationConnectionID(pathID protocol.PathID, seqNum uint64) error {
	m.assertNotClosed()
	pathCIDs, ok := m.connIDsByPath[pathID]
	if !ok { return fmt.Errorf("cannot retire CID for unknown path %d", pathID) }

	info, ok := pathCIDs[seqNum]
	if !ok { return fmt.Errorf("CID with sequence number %d not found on path %d", seqNum, pathID) }

	m.removeResetTokenFunc(info.StatelessResetToken)
	delete(pathCIDs, seqNum) // Remove from available CIDs for this path

	m.logger.Debugf("Queuing PATH_RETIRE_CONNECTION_ID for path %d, peer's CID seq %d (CID: %s)", pathID, seqNum, info.ConnectionID)
	m.queueControlFrameFunc(&wire.PathRetireConnectionIDFrame{PathIdentifier: pathID, SequenceNumber: seqNum})

	// If this was the active DCID for the path, select a new one.
	if activeSeq, isActive := m.activeDestConnIDSeqNumByPath[pathID]; isActive && activeSeq == seqNum {
		delete(m.activeDestConnIDByPath, pathID)
		delete(m.activeDestConnIDSeqNumByPath, pathID)

		var nextActiveInfo *connIDInfo
		for _, availableInfo := range pathCIDs { // Iterate remaining CIDs for this path
			if nextActiveInfo == nil || availableInfo.SequenceNumber > nextActiveInfo.SequenceNumber {
				nextActiveInfo = availableInfo
			}
		}
		if nextActiveInfo != nil {
			m.activeDestConnIDByPath[pathID] = nextActiveInfo.ConnectionID
			m.activeDestConnIDSeqNumByPath[pathID] = nextActiveInfo.SequenceNumber
			m.logger.Debugf("Updated active DCID for path %d to %s (seq %d)", pathID, nextActiveInfo.ConnectionID, nextActiveInfo.SequenceNumber)
		} else {
			m.logger.Debugf("Path %d has no more active CIDs after retiring seq %d", pathID, seqNum)
		}
	}
	return nil
}

func (m *connIDManager) GetDestinationConnectionID(pathID protocol.PathID) (protocol.ConnectionID, bool) {
	m.assertNotClosed()
	// TODO: Implement CID rotation based on packets sent, similar to old `Get()` logic but per-path.
	// For now, just return the currently set active one for the path.
	cid, ok := m.activeDestConnIDByPath[pathID]
	return cid, ok
}

func (m *connIDManager) Get() protocol.ConnectionID {
	cid, _ := m.GetDestinationConnectionID(protocol.InitialPathID)
	return cid
}

func (m *connIDManager) ChangeInitialConnID(id protocol.ConnectionID) {
	m.assertNotClosed()
	path0ID := protocol.InitialPathID
	if info, ok := m.connIDsByPath[path0ID][0]; ok {
		if info.StatelessResetToken != (protocol.StatelessResetToken{}) { // Check if not zero token
			m.removeResetTokenFunc(info.StatelessResetToken)
		}
		info.ConnectionID = id
		info.StatelessResetToken = protocol.StatelessResetToken{} // Reset token, expecting new one via SetStatelessResetTokenFromTP
		m.activeDestConnIDByPath[path0ID] = id
		m.activeDestConnIDSeqNumByPath[path0ID] = 0 // Ensure seq num is 0
	} else {
		m.logger.Errorf("ChangeInitialConnID called but Path 0 initial CID info not found")
	}
}

// SetStatelessResetTokenFromTP sets the stateless reset token for Path 0, sequence 0.
// This is called when the server provides a stateless reset token in its transport parameters.
func (m *connIDManager) SetStatelessResetTokenFromTP(token protocol.StatelessResetToken) {
	m.assertNotClosed()
	path0ID := protocol.InitialPathID
	if info, ok := m.connIDsByPath[path0ID][0]; ok && info.SequenceNumber == 0 {
		if info.StatelessResetToken != (protocol.StatelessResetToken{}) {
			m.removeResetTokenFunc(info.StatelessResetToken)
		}
		info.StatelessResetToken = token
		m.addResetTokenFunc(token)
	} else {
		m.logger.Errorf("SetStatelessResetTokenFromTP called but Path 0 initial CID (seq 0) not found or info mismatch")
	}
}

func (m *connIDManager) SentPacket(pathID protocol.PathID) {
	// This was for self-initiated CID rotation.
	// With PATH_NEW_CONNECTION_ID, peer controls when we get new CIDs.
	// We control retiring them via PATH_RETIRE_CONNECTION_ID.
	// Rotation to use a *different available* CID for a path is a local choice.
	// This counter might be reused for that local choice.
	// For now, this method is a no-op or can be removed if CID rotation logic is fully driven by Add/Retire.
}

func (m *connIDManager) SetHandshakeComplete() {
	m.handshakeComplete = true
}

func (m *connIDManager) IsActiveStatelessResetToken(token protocol.StatelessResetToken) bool {
	m.assertNotClosed()
	for pathID := range m.connIDsByPath {
		activeCID, ok := m.activeDestConnIDByPath[pathID]
		if !ok { continue }

		activeSeqNum := m.activeDestConnIDSeqNumByPath[pathID]
		if info, ok := m.connIDsByPath[pathID][activeSeqNum]; ok {
			if info.ConnectionID.Equal(activeCID) && info.StatelessResetToken == token {
				return true
			}
		}
	}
	return false
}

func (m *connIDManager) Close() {
	if m.closed { return }
	for _, pathCIDs := range m.connIDsByPath {
		for _, info := range pathCIDs {
			m.removeResetTokenFunc(info.StatelessResetToken)
		}
	}
	m.connIDsByPath = nil
	m.activeDestConnIDByPath = nil
	m.activeDestConnIDSeqNumByPath = nil
	m.highestRetiredSeqNumByPath = nil
	m.closed = true
}

func (m *connIDManager) assertNotClosed() {
	if m.closed {
		panic("connIDManager used after Close")
	}
}

[end of conn_id_manager.go]
