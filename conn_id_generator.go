package quic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	// Grace period for retiring a connection ID, to allow for packets in flight.
	// This should ideally be based on PTO of the path the CID was used on.
	// For now, a fixed conservative value.
	defaultRetireCIDGracePeriod = 5 * time.Second // TODO: Make this PTO-based
)

// issuedConnID stores information about a connection ID that we issued to the peer.
type issuedConnID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
	IsActive            bool      // Is this CID currently considered active by us (not yet told to retire by peer)
	RetireTime          time.Time // Time after which this CID can be removed from packet handler map, after peer acknowledges retirement
	PathID              protocol.PathID
}

// pathCIDIssuanceState holds the state for CIDs issued by us for a specific path.
type pathCIDIssuanceState struct {
	currentSeqNum  uint64
	issuedCIDs     map[uint64]*issuedConnID // map sequence number to CID info
	activeCIDCount int                      // Number of CIDs issued for this path that peer hasn't retired yet
}

// ConnectionIDGenerator is responsible for generating and managing connection IDs that we issue.
// It is now path-aware.
type ConnectionIDGenerator struct {
	mutex sync.Mutex

	cidStateByPath map[protocol.PathID]*pathCIDIssuanceState

	connIDLimit uint64 // Our local limit on how many CIDs we issue per path (from Config.ActiveConnectionIDLimit)

	// Function to get our own advertised MAX_PATH_ID.
	// We should not issue CIDs for paths beyond this limit.
	getOurMaxPathIDFunc func() protocol.PathID

	// For custom CID generation, can be nil for default.
	newConnectionIDFunc func() (protocol.ConnectionID, error)
	// For custom SRT generation.
	newStatelessResetTokenFunc func(protocol.ConnectionID) protocol.StatelessResetToken

	// Callbacks to interact with the connection/server
	queueControlFrameFunc   func(wire.Frame)
	addConnectionIDFunc     func(protocol.ConnectionID)    // To add to packet handler map
	removeConnectionIDFunc  func(protocol.ConnectionID)    // To remove from packet handler map
	replaceWithClosedFunc func([]protocol.ConnectionID, []byte, time.Duration) // To replace CIDs with closed state

	handshakeComplete bool
	closed            bool
	logger            utils.Logger

	// Used for retiring CIDs based on a grace period
	// TODO: This should ideally use path-specific PTOs.
	retireCIDGracePeriod time.Duration
}

// NewConnectionIDGenerator creates a new ConnectionIDGenerator.
func NewConnectionIDGenerator(
	initialOurConnID protocol.ConnectionID,
	initialSRT protocol.StatelessResetToken,
	connIDLimit uint64, // From Config.ActiveConnectionIDLimit
	getOurMaxPathIDFunc func() protocol.PathID,
	newConnectionIDFunc func() (protocol.ConnectionID, error), // Optional
	newStatelessResetTokenFunc func(protocol.ConnectionID) protocol.StatelessResetToken, // Optional
	queueControlFrame func(wire.Frame),
	addConnectionID func(protocol.ConnectionID),
	removeConnectionID func(protocol.ConnectionID),
	replaceWithClosed func([]protocol.ConnectionID, []byte, time.Duration),
	logger utils.Logger,
) *ConnectionIDGenerator {
	if newStatelessResetTokenFunc == nil {
		newStatelessResetTokenFunc = func(_ protocol.ConnectionID) protocol.StatelessResetToken {
			var token protocol.StatelessResetToken
			_, _ = rand.Read(token[:])
			return token
		}
	}
	if newConnectionIDFunc == nil {
		newConnectionIDFunc = func() (protocol.ConnectionID, error) {
			return protocol.GenerateConnectionID(protocol.DefaultConnectionIDLength)
		}
	}

	g := &ConnectionIDGenerator{
		cidStateByPath:             make(map[protocol.PathID]*pathCIDIssuanceState),
		connIDLimit:                connIDLimit,
		getOurMaxPathIDFunc:        getOurMaxPathIDFunc,
		newConnectionIDFunc:        newConnectionIDFunc,
		newStatelessResetTokenFunc: newStatelessResetTokenFunc,
		queueControlFrameFunc:      queueControlFrame,
		addConnectionIDFunc:        addConnectionID,
		removeConnectionIDFunc:     removeConnectionID,
		replaceWithClosedFunc:      replaceWithClosed,
		logger:                     logger,
		retireCIDGracePeriod:       defaultRetireCIDGracePeriod,
	}

	// Initialize state for Path ID 0
	path0ID := protocol.InitialPathID
	path0State := &pathCIDIssuanceState{
		currentSeqNum:  0, // Initial CID has sequence number 0
		issuedCIDs:     make(map[uint64]*issuedConnID),
		activeCIDCount: 0, // Will be 1 after adding the initial CID
	}
	g.cidStateByPath[path0ID] = path0State

	initialCIDInfo := &issuedConnID{
		SequenceNumber:      0,
		ConnectionID:        initialOurConnID,
		StatelessResetToken: initialSRT,
		IsActive:            true,
		PathID:              path0ID,
	}
	path0State.issuedCIDs[0] = initialCIDInfo
	path0State.activeCIDCount = 1
	g.addConnectionIDFunc(initialOurConnID) // Add initial SCID to packet handler map

	return g
}

// GenerateNewConnectionID generates a new CID for a given path and queues a PATH_NEW_CONNECTION_ID frame.
func (g *ConnectionIDGenerator) GenerateNewConnectionID(pathID protocol.PathID, retirePriorToOldCIDs bool) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.closed { return errors.New("ConnectionIDGenerator closed") }

	ourMaxPathID := protocol.PathID(0) // Default if func is nil
	if g.getOurMaxPathIDFunc != nil {
		ourMaxPathID = g.getOurMaxPathIDFunc()
	}
	if pathID > ourMaxPathID && pathID != protocol.InitialPathID { // Path 0 always allowed implicitly
		return fmt.Errorf("cannot generate CID for path %d: exceeds our MAX_PATH_ID %d", pathID, ourMaxPathID)
	}

	pathState, ok := g.cidStateByPath[pathID]
	if !ok { // First CID for this path (other than potentially Path 0 initial)
		pathState = &pathCIDIssuanceState{
			currentSeqNum:  0, // Sequence numbers are per-path
			issuedCIDs:     make(map[uint64]*issuedConnID),
			activeCIDCount: 0,
		}
		g.cidStateByPath[pathID] = pathState
	}

	if uint64(pathState.activeCIDCount) >= g.connIDLimit {
		// We have issued enough CIDs for this path that are not yet retired by the peer.
		// We could queue a PATH_CIDS_BLOCKED frame here, or rely on higher level logic.
		g.logger.Debugf("CID limit reached for path %d. Cannot issue new CID.", pathID)
		return qerr.NewError(qerr.ConnectionIDLimitError, fmt.Sprintf("cannot issue new CID for path %d: limit reached", pathID))
	}

	newCID, err := g.newConnectionIDFunc()
	if err != nil { return err }
	newSRT := g.newStatelessResetTokenFunc(newCID)
	seqNum := pathState.currentSeqNum

	cidInfo := &issuedConnID{
		SequenceNumber:      seqNum,
		ConnectionID:        newCID,
		StatelessResetToken: newSRT,
		IsActive:            true,
		PathID:              pathID,
	}
	pathState.issuedCIDs[seqNum] = cidInfo
	pathState.activeCIDCount++
	g.addConnectionIDFunc(newCID) // Add to packet handler map

	retirePriorToVal := uint64(0)
	if retirePriorToOldCIDs {
		// Example logic: if we are at limit, retire the one that makes space.
		// More robust: retire CIDs with seqNum < currentSeqNum - connIDLimit + 1
		if uint64(pathState.activeCIDCount) >= g.connIDLimit && pathState.currentSeqNum >= g.connIDLimit {
			retirePriorToVal = pathState.currentSeqNum - g.connIDLimit + 1
		}
		// This logic for RetirePriorTo needs to be robust.
		// It should retire CIDs such that the number of active CIDs peer knows about for this path
		// does not exceed g.connIDLimit.
		// For now, simple RetirePriorTo if we're at the limit.
		// A better approach might be to retire the oldest one if we have connIDLimit active CIDs.
	}


	frame := &wire.PathNewConnectionIDFrame{
		PathIdentifier:      pathID,
		SequenceNumber:      seqNum,
		RetirePriorTo:       retirePriorToVal,
		ConnectionID:        newCID,
		StatelessResetToken: newSRT,
	}
	g.queueControlFrameFunc(frame)
	g.logger.Debugf("Queued PATH_NEW_CONNECTION_ID for path %d: SeqNum %d, CID %s, RetirePriorTo %d", pathID, seqNum, newCID, retirePriorToVal)

	pathState.currentSeqNum++
	return nil
}

// Retire is called when the peer sends a PATH_RETIRE_CONNECTION_ID frame for a CID we issued on a specific path.
func (g *ConnectionIDGenerator) Retire(pathID protocol.PathID, seqNum uint64, rcvTime time.Time) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.closed { return errors.New("ConnectionIDGenerator closed") }

	pathState, ok := g.cidStateByPath[pathID]
	if !ok {
		return fmt.Errorf("received PATH_RETIRE_CONNECTION_ID for unknown path %d", pathID)
	}
	cidInfo, ok := pathState.issuedCIDs[seqNum]
	if !ok {
		// Peer might be retiring a CID we've already forgotten or one that never existed.
		// This is a protocol violation if the sequence number is higher than what we've issued.
		if seqNum >= pathState.currentSeqNum {
			return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: fmt.Sprintf("peer retired unknown CID seq %d on path %d", seqNum, pathID)}
		}
		// Otherwise, it's a CID we already processed for retirement, ignore.
		g.logger.Debugf("Peer retired already processed/unknown CID seq %d on path %d", seqNum, pathID)
		return nil
	}

	if !cidInfo.IsActive {
		g.logger.Debugf("Peer retired already inactive CID seq %d on path %d", seqNum, pathID)
		// If it's already inactive but not yet passed RetireTime, update RetireTime if this is sooner.
		// For now, just return if already marked inactive.
		return nil
	}

	g.logger.Debugf("Peer retired CID %s (seq %d) on path %d. Will be removed after grace period.", cidInfo.ConnectionID, seqNum, pathID)
	cidInfo.IsActive = false
	cidInfo.RetireTime = rcvTime.Add(g.retireCIDGracePeriod) // Set time for actual removal
	pathState.activeCIDCount--

	// TODO: Potentially generate a new CID to replace this one if below active limit.
	// This could be triggered here or by a separate mechanism that monitors activeCIDCount.
	// if uint64(pathState.activeCIDCount) < g.connIDLimit {
	//    g.GenerateNewConnectionID(pathID, true) // Example: true to potentially retire older ones
	// }
	return nil
}

// GetInitialConnID returns the initial Source Connection ID.
func (g *ConnectionIDGenerator) GetInitialConnID() protocol.ConnectionID {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if pathState, ok := g.cidStateByPath[protocol.InitialPathID]; ok {
		if info, ok2 := pathState.issuedCIDs[0]; ok2 {
			return info.ConnectionID
		}
	}
	panic("initial connection ID not found")
}

// GetConnectionIDSequenceNumber returns the sequence number for a given CID.
// This is needed by multiPathManager when creating quicPath objects.
// This might be inefficient and indicates CIDs should perhaps be globally unique for easy lookup.
func (g *ConnectionIDGenerator) GetConnectionIDSequenceNumber(cid protocol.ConnectionID) uint64 {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	for _, pathState := range g.cidStateByPath {
		for seqNum, info := range pathState.issuedCIDs {
			if info.ConnectionID.Equal(cid) {
				return seqNum
			}
		}
	}
	return protocol.InvalidPathID // Using as a sentinel for not found, though it's a PathID type.
}

// GetActiveCIDCount returns the number of active CIDs currently issued for a given path.
// Returns 0 if the path does not exist or has no active CIDs.
func (g *ConnectionIDGenerator) GetActiveCIDCount(pathID protocol.PathID) int {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if pathState, ok := g.cidStateByPath[pathID]; ok {
		return pathState.activeCIDCount
	}
	return 0
}

// RemoveRetiredConnIDs is called periodically to remove CIDs that have passed their retirement grace period.
func (g *ConnectionIDGenerator) RemoveRetiredConnIDs(now time.Time) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.closed { return }

	for pathID, pathState := range g.cidStateByPath {
		for seqNum, cidInfo := range pathState.issuedCIDs {
			if !cidInfo.IsActive && !cidInfo.RetireTime.IsZero() && !now.Before(cidInfo.RetireTime) {
				g.logger.Debugf("Removing retired CID %s (seq %d) from path %d packet handler map", cidInfo.ConnectionID, seqNum, pathID)
				g.removeConnectionIDFunc(cidInfo.ConnectionID)
				delete(pathState.issuedCIDs, seqNum)
			}
		}
	}
}

func (g *ConnectionIDGenerator) SetHandshakeComplete() {
	g.mutex.Lock()
	g.handshakeComplete = true
	g.mutex.Unlock()
	// After handshake, we might want to issue more CIDs for path 0 if needed.
	// g.GenerateNewConnectionID(protocol.InitialPathID, true) // Example
}

func (g *ConnectionIDGenerator) RemoveAll() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.closed { return }
	for pathID, pathState := range g.cidStateByPath {
		for _, cidInfo := range pathState.issuedCIDs {
			g.removeConnectionIDFunc(cidInfo.ConnectionID)
		}
		delete(g.cidStateByPath, pathID)
	}
}

func (g *ConnectionIDGenerator) ReplaceWithClosed(closedPackets []byte, closeDuration time.Duration) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.closed { return }
	var cids []protocol.ConnectionID
	for _, pathState := range g.cidStateByPath {
		for _, info := range pathState.issuedCIDs {
			if info.IsActive { // Only replace CIDs that might still be in use by peer or network
				cids = append(cids, info.ConnectionID)
			}
		}
	}
	g.replaceWithClosedFunc(cids, closedPackets, closeDuration)
	g.closed = true // No new CIDs should be generated after this.
}

func (g *ConnectionIDGenerator) Close() {
	g.mutex.Lock()
	g.closed = true
	g.mutex.Unlock()
}

[end of conn_id_generator.go]
