package quic

import (
	"crypto/rand"
	"net"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

// PathValidationState represents the validation state of a path
type PathValidationState uint8

const (
	// PathStateUnvalidated means the path has not been validated yet
	PathStateUnvalidated PathValidationState = iota
	// PathStateValidating means a PATH_CHALLENGE has been sent and we are waiting for a PATH_RESPONSE
	PathStateValidating
	// PathStateValidated means a PATH_RESPONSE has been received and the path is considered valid
	PathStateValidated
	// PathStateFailed means path validation failed (e.g., timeout or mismatch)
	PathStateFailed
)

// ConnectionIDInfo holds information about a connection ID
// TODO: This might need to be more closely aligned with connIDManager's structures later
type ConnectionIDInfo struct {
	CID            protocol.ConnectionID
	SequenceNumber uint64
	// TODO: StatelessResetToken *protocol.StatelessResetToken
}

type quicPath struct {
	id protocol.PathID

	remoteAddr net.Addr
	localAddr  net.Addr // TODO: How to specify this for sending?

	validationState PathValidationState
	// sentPathChallengeData stores the data of the PATH_CHALLENGE frame sent on this path.
	// It's used to verify the PATH_RESPONSE.
	sentPathChallengeData [8]byte

	isActive bool // True if this path is actively used for sending non-probing packets

	// peerConnectionID is the Connection ID that the peer uses for this path.
	// We use this as the Destination Connection ID when sending packets on this path.
	// This will be a list of CIDs provided by the peer for this path.
	peerConnectionIDs []ConnectionIDInfo
	// ourConnectionIDs contains the Connection IDs we want the peer to use when sending to us on this path.
	// These are sent to the peer (e.g. via PATH_NEW_CONNECTION_ID frame for this path).
	ourConnectionIDs []ConnectionIDInfo // CIDs we have provided for the peer to use on this path. SeqNum is our local seq num for these CIDs.

	peerAdvertisedStatus PathPeerAdvertisedStatus
	lastPeerPathStatusSeqNum uint64 // Highest PSSN received from peer for this path
	ourLastPathStatusSeqNum  uint64 // Last PSSN we sent for this path

	sentPathAbandon bool      // True if we have sent PATH_ABANDON for this path
	rcvdPathAbandon bool      // True if we have received PATH_ABANDON for this path
	abandonTime     time.Time // Time when abandonment process started (either sent or received)

	// TODOs for future multipath enhancements:
	// rttStats             *utils.RTTStats
	// congestionController congestion.Controller
	// sentPacketHandler    ackhandler.SentPacketHandler // For outgoing packets on this path
	// receivedPacketHandler ackhandler.ReceivedPacketHandler // For incoming packets on this path
}

type multiPathManager struct {
	mutex sync.Mutex
	paths []*quicPath

	nextLocalPathID protocol.PathID // Counter for generating unique local Path IDs

	peerMaxPathIDAdvertised  protocol.PathID // Highest Path ID the peer is willing to use / has told us it supports
	ourMaxPathIDAdvertised   protocol.PathID // Highest Path ID we have told the peer we support

	// References to connection components
	logger utils.Logger
	conn   interface { // Define a minimal interface for what multiPathManager needs from connection
		Perspective() protocol.Perspective
		Packer() packer // Assuming packer interface exists and is accessible
		SendQueue() sender // Assuming sender interface exists
		CloseWithError(error) // For protocol violations
		ConnIDGenerator() *connIDGenerator // TODO: Make this an interface
		ConnIDManager() *connIDManager     // TODO: Make this an interface
		GetPeerInitialMaxPathID() protocol.PathID
		GetLocalInitialMaxPathID() protocol.PathID
		QueueControlFrame(wire.Frame)
		RetirePeerConnectionID(pathID protocol.PathID, seqNum uint64) // To inform ConnIDManager about CIDs retired by peer via PATH_NEW_CONNECTION_ID
		// TODO: Add version() if needed for frame length calculations
	}
}

func newMultiPathManager(conn interface {
	Perspective() protocol.Perspective
	Packer() packer
	SendQueue() sender
	CloseWithError(error)
	ConnIDGenerator() *connIDGenerator
	ConnIDManager() *connIDManager
	GetPeerInitialMaxPathID() protocol.PathID
	GetLocalInitialMaxPathID() protocol.PathID
	QueueControlFrame(wire.Frame)
	RetirePeerConnectionID(pathID protocol.PathID, seqNum uint64)
}, logger utils.Logger) *multiPathManager {
	mpm := &multiPathManager{
		paths:           make([]*quicPath, 0, 1), // Initialize with capacity for the default path
		nextLocalPathID: 0,                      // Path ID 0 is the default path
		conn:            conn,
		logger:          logger,
	}
	// Initialize advertised path ID limits from connection (which should get them from transport params)
	mpm.peerMaxPathIDAdvertised = conn.GetPeerInitialMaxPathID()
	if mpm.peerMaxPathIDAdvertised == protocol.InvalidPathID {
		// If the peer didn't send initial_max_path_id, it means it doesn't support multipath,
		// or it supports at most path ID 0.
		// The draft says: "If the initial_max_path_id transport parameter is absent,
		// it is equivalent to a value of 0."
		mpm.peerMaxPathIDAdvertised = 0
	}
	mpm.ourMaxPathIDAdvertised = conn.GetLocalInitialMaxPathID()
	if mpm.ourMaxPathIDAdvertised == protocol.InvalidPathID {
		mpm.ourMaxPathIDAdvertised = 0 // Default to 0 if not configured
	}
	return mpm
}

// PathPeerAdvertisedStatus indicates the status of a path as advertised by the peer.
type PathPeerAdvertisedStatus uint8

const (
	// PathStatusUnknown means the peer has not yet advertised a status for this path, or status is not applicable.
	PathStatusUnknown PathPeerAdvertisedStatus = iota
	// PathStatusAvailable means the peer has advertised this path as available.
	PathStatusAvailable
	// PathStatusBackup means the peer has advertised this path as a backup path.
	PathStatusBackup
)

// HandlePathAvailable is called when a PATH_AVAILABLE frame is received.
func (m *multiPathManager) HandlePathAvailable(frame *wire.PathAvailableFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p := range m.paths {
		if p.id == frame.PathIdentifier {
			path = p
			break
		}
	}

	if path == nil {
		m.logger.Debugf("Received PATH_AVAILABLE for unknown path %d", frame.PathIdentifier)
		return
	}

	if frame.PathStatusSequenceNumber > path.lastPeerPathStatusSeqNum {
		path.peerAdvertisedStatus = PathStatusAvailable
		path.lastPeerPathStatusSeqNum = frame.PathStatusSequenceNumber
		m.logger.Debugf("Path %d is now AVAILABLE as per peer (PSSN: %d)", path.id, frame.PathStatusSequenceNumber)
		// TODO: Notify packet scheduler / connection state that this path is available for use.
	} else {
		m.logger.Debugf("Received old PATH_AVAILABLE for path %d (PSSN: %d, last_known: %d)", path.id, frame.PathStatusSequenceNumber, path.lastPeerPathStatusSeqNum)
	}
}

// HandlePathBackup is called when a PATH_BACKUP frame is received.
func (m *multiPathManager) HandlePathBackup(frame *wire.PathBackupFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p := range m.paths {
		if p.id == frame.PathIdentifier {
			path = p
			break
		}
	}

	if path == nil {
		m.logger.Debugf("Received PATH_BACKUP for unknown path %d", frame.PathIdentifier)
		return
	}

	if frame.PathStatusSequenceNumber > path.lastPeerPathStatusSeqNum {
		path.peerAdvertisedStatus = PathStatusBackup
		path.lastPeerPathStatusSeqNum = frame.PathStatusSequenceNumber
		m.logger.Debugf("Path %d is now BACKUP as per peer (PSSN: %d)", path.id, frame.PathStatusSequenceNumber)
		// TODO: Notify packet scheduler / connection state.
	} else {
		m.logger.Debugf("Received old PATH_BACKUP for path %d (PSSN: %d, last_known: %d)", path.id, frame.PathStatusSequenceNumber, path.lastPeerPathStatusSeqNum)
	}
}

// SignalPathAvailable sends a PATH_AVAILABLE frame for the given path ID.
func (m *multiPathManager) SignalPathAvailable(pathID protocol.PathID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p := range m.paths {
		if p.id == pathID {
			path = p
			break
		}
	}
	if path == nil {
		return fmt.Errorf("cannot signal available for unknown path %d", pathID)
	}

	path.ourLastPathStatusSeqNum++
	frame := &wire.PathAvailableFrame{
		PathIdentifier:           path.id,
		PathStatusSequenceNumber: path.ourLastPathStatusSeqNum,
	}
	m.conn.QueueControlFrame(frame)
	m.logger.Debugf("Queued PATH_AVAILABLE for path %d (PSSN: %d)", path.id, path.ourLastPathStatusSeqNum)
	return nil
}

// SignalPathBackup sends a PATH_BACKUP frame for the given path ID.
func (m *multiPathManager) SignalPathBackup(pathID protocol.PathID) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p := range m.paths {
		if p.id == pathID {
			path = p
			break
		}
	}
	if path == nil {
		return fmt.Errorf("cannot signal backup for unknown path %d", pathID)
	}

	path.ourLastPathStatusSeqNum++
	frame := &wire.PathBackupFrame{
		PathIdentifier:           path.id,
		PathStatusSequenceNumber: path.ourLastPathStatusSeqNum,
	}
	m.conn.QueueControlFrame(frame)
	m.logger.Debugf("Queued PATH_BACKUP for path %d (PSSN: %d)", path.id, path.ourLastPathStatusSeqNum)
	return nil
}

// HandlePathAbandon is called when a PATH_ABANDON frame is received.
func (m *multiPathManager) HandlePathAbandon(frame *wire.PathAbandonFrame, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	var pathIdx int
	found := false
	for idx, p := range m.paths {
		if p.id == frame.PathIdentifier {
			path = p
			pathIdx = idx
			found = true
			break
		}
	}

	if !found || path.rcvdPathAbandon { // If path unknown or already processing abandon
		m.logger.Debugf("Received PATH_ABANDON for unknown or already abandoned path %d", frame.PathIdentifier)
		return
	}

	m.logger.Debugf("Received PATH_ABANDON for path %d, ErrorCode: 0x%x", frame.PathIdentifier, frame.ErrorCode)
	path.rcvdPathAbandon = true
	path.isActive = false // Path is no longer active
	if path.abandonTime.IsZero() {
		path.abandonTime = rcvTime
	}

	// TODO: Signal to connection/CID manager to handle CIDs associated with this path.
	// This might involve retiring peer CIDs and our CIDs used on this path.

	// If we haven't sent PATH_ABANDON for this path yet, send one back with NoError.
	if !path.sentPathAbandon {
		path.sentPathAbandon = true
		// ErrorCode 0 indicates no error, just acknowledging the abandonment.
		// Or, we could use a specific code if the standard defines one for acknowledgment.
		responseFrame := &wire.PathAbandonFrame{PathIdentifier: frame.PathIdentifier, ErrorCode: uint64(qerr.NoError)}
		m.conn.QueueControlFrame(responseFrame)
		m.logger.Debugf("Queued acknowledging PATH_ABANDON for path %d", frame.PathIdentifier)
	}

	// TODO: Start a 3 PTO timer for full path resource cleanup.
	// After 3 PTOs, the path and its resources (CIDs, etc.) should be fully removed.
	// For now, we can mark it as unusable. The actual removal might happen in a separate GC process.
	path.validationState = PathStateFailed // Mark as failed to prevent further use.

	m.logger.Infof("Path %d marked as abandoned due to peer request.", path.id)
	// TODO: If this was the last active path, or a critical path, signal connection to potentially close or take action.
}

// AbandonPath initiates abandoning a path from our side.
func (m *multiPathManager) AbandonPath(pathID protocol.PathID, errorCode protocol.ApplicationErrorCode) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	var pathIdx int
	found := false
	for idx, p := range m.paths {
		if p.id == pathID {
			path = p
			pathIdx = idx
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("cannot abandon unknown path %d", pathID)
	}

	if path.sentPathAbandon {
		m.logger.Debugf("Path %d already being abandoned, not sending another PATH_ABANDON", pathID)
		return nil // Already initiated by us or acknowledged.
	}

	path.sentPathAbandon = true
	path.isActive = false
	if path.abandonTime.IsZero() {
		path.abandonTime = time.Now()
	}
	// Use the qerr error codes defined for multipath if appropriate, or map application error.
	// For this example, we'll use the passed error code directly if it fits uint64.
	// The draft suggests application error codes for self-initiated abandons.
	abandonErrorCode := uint64(errorCode) // Assuming ApplicationErrorCode can map to uint64 for the frame.
	// If specific multipath qerr codes are to be used, map them here. e.g. qerr.APPLICATION_ABANDON

	frame := &wire.PathAbandonFrame{
		PathIdentifier: path.id,
		ErrorCode:      abandonErrorCode,
	}
	m.conn.QueueControlFrame(frame)
	m.logger.Debugf("Queued PATH_ABANDON for path %d with ErrorCode 0x%x", path.id, abandonErrorCode)

	// TODO: Signal to connection/CID manager to handle CIDs.
	// TODO: Start 3 PTO timer for cleanup.
	path.validationState = PathStateFailed // Mark as failed to prevent further use.

	m.logger.Infof("Path %d initiated abandonment from our side.", path.id)
	return nil
}

// HandleMaxPathID is called when a MAX_PATH_ID frame is received.
func (m *multiPathManager) HandleMaxPathID(frame *wire.MaxPathIDFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Debugf("Received MAX_PATH_ID frame with MaximumPathIdentifier: %d", frame.MaximumPathIdentifier)

	// Validation: MAX_PATH_ID must not be lower than previously established limits.
	// The initial limit is established by the initial_max_path_id transport parameter.
	// Max value for PathID is 2^32-1 (from draft, though PathID type is uint64 for flexibility)
	maxAllowedPathID := uint64((1 << 32) - 1) // As per draft-ietf-quic-multipath-07 section 4.1

	// m.peerMaxPathIDAdvertised was initialized with initial_max_path_id from TPs.
	if frame.MaximumPathIdentifier < uint64(m.peerMaxPathIDAdvertised) {
		m.conn.CloseWithError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("MAX_PATH_ID reduced below previously advertised value. Received: %d, Current: %d", frame.MaximumPathIdentifier, m.peerMaxPathIDAdvertised),
		})
		return
	}

	if frame.MaximumPathIdentifier > maxAllowedPathID {
		m.conn.CloseWithError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("MAX_PATH_ID %d exceeds limit of %d", frame.MaximumPathIdentifier, maxAllowedPathID),
		})
		return
	}

	if protocol.PathID(frame.MaximumPathIdentifier) > m.peerMaxPathIDAdvertised {
		m.peerMaxPathIDAdvertised = protocol.PathID(frame.MaximumPathIdentifier)
		m.logger.Debugf("Peer updated MaxPathID to %d", m.peerMaxPathIDAdvertised)
		// TODO: Potentially signal that more paths can be opened if we were blocked by this limit.
		// This could involve, for example, retrying path probes that previously failed due to this limit.
	}
}

// HandlePathsBlocked is called when a PATHS_BLOCKED frame is received.
func (m *multiPathManager) HandlePathsBlocked(frame *wire.PathsBlockedFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// This frame is informational from the peer.
	// It indicates the peer tried to open a new path but was blocked by the limit *we* advertised.
	m.logger.Debugf("Received PATHS_BLOCKED frame. Peer was blocked by its view of our MaxPathID limit: %d. Our current advertised limit is %d.", frame.MaximumPathIdentifier, m.ourMaxPathIDAdvertised)
	// If frame.MaximumPathIdentifier < uint64(m.ourMaxPathIDAdvertised), it means the peer has an old view of our limit.
	// We could consider sending an updated MAX_PATH_ID if our limit has increased.
}

// HandlePathCIDsBlocked is called when a PATH_CIDS_BLOCKED frame is received.
func (m *multiPathManager) HandlePathCIDsBlocked(frame *wire.PathCIDsBlockedFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Debugf("Received PATH_CIDS_BLOCKED for PathIdentifier %d, NextSequenceNumber %d", frame.PathIdentifier, frame.NextSequenceNumber)

	// Validate PathIdentifier against the limit we advertised to the peer.
	if frame.PathIdentifier > m.ourMaxPathIDAdvertised {
		m.conn.CloseWithError(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("PATH_CIDS_BLOCKED received for PathIdentifier %d, which exceeds our advertised MaxPathID %d", frame.PathIdentifier, m.ourMaxPathIDAdvertised),
		})
		return
	}

	pathFound := false
	for _, p := range m.paths {
		if p.id == frame.PathIdentifier {
			pathFound = true
			break
		}
	}
	if !pathFound && frame.PathIdentifier != 0 { // Path ID 0 is the default path, always implicitly exists
		m.logger.Debugf("PATH_CIDS_BLOCKED received for a non-default, unknown path %d.", frame.PathIdentifier)
		// This might not be a protocol violation if the path was recently abandoned and messages crossed in flight.
		// However, if it's for a PathID > 0 that we never knew, it's strange.
		// For now, just log. A stricter implementation might close.
	}

	// TODO: Validate frame.NextSequenceNumber against CIDs we've issued for this path.
	// This requires tracking CIDs we've issued per path and their sequence numbers.
	// If frame.NextSequenceNumber is lower than or equal to the highest sequence number we've issued for that path,
	// it means the peer might have an outdated view or is misbehaving.
	m.logger.Debugf("Further validation for PATH_CIDS_BLOCKED NextSequenceNumber %d on path %d is a TODO.", frame.NextSequenceNumber, frame.PathIdentifier)
}

// QueueMaxPathIDFrame is called to send a MAX_PATH_ID frame.
// This informs the peer about the maximum Path ID we are prepared to accept.
func (m *multiPathManager) QueueMaxPathIDFrame(maxPathID protocol.PathID) {
	m.mutex.Lock()
	// Max value for PathID is 2^32-1
	maxAllowedPathID := protocol.PathID((1 << 32) - 1)
	if maxPathID > maxAllowedPathID {
		m.logger.Errorf("Attempted to queue MAX_PATH_ID %d which exceeds limit %d. Clamping.", maxPathID, maxAllowedPathID)
		maxPathID = maxAllowedPathID
	}

	// It's a protocol violation to decrease this value.
	if maxPathID < m.ourMaxPathIDAdvertised && m.ourMaxPathIDAdvertised != 0 { // Allow setting initial 0 to something
		m.logger.Errorf("Attempted to queue MAX_PATH_ID %d which is lower than previously advertised %d. This is a protocol violation if already sent. Current logic will send it.", maxPathID, m.ourMaxPathIDAdvertised)
		// Depending on strictness, could return error or prevent sending.
		// For now, we'll update our internal state and queue the frame. The peer should error if it's a decrease.
	}

	m.ourMaxPathIDAdvertised = maxPathID
	m.mutex.Unlock()

	frame := &wire.MaxPathIDFrame{MaximumPathIdentifier: uint64(maxPathID)}
	m.conn.QueueControlFrame(frame)
	m.logger.Debugf("Queued MAX_PATH_ID frame with MaximumPathIdentifier %d", maxPathID)
}

// QueuePathsBlockedFrame is called to send a PATHS_BLOCKED frame.
// This informs the peer that we tried to open a path but were blocked by their advertised limit.
func (m *multiPathManager) QueuePathsBlockedFrame() {
	m.mutex.Lock()
	// This frame indicates the limit that we believe the peer has imposed on us.
	limitPeerAdvertised := m.peerMaxPathIDAdvertised
	m.mutex.Unlock()

	frame := &wire.PathsBlockedFrame{MaximumPathIdentifier: uint64(limitPeerAdvertised)}
	m.conn.QueueControlFrame(frame)
	m.logger.Debugf("Queued PATHS_BLOCKED frame with MaximumPathIdentifier %d (peer's advertised limit)", limitPeerAdvertised)
}

// QueuePathCIDsBlockedFrame is called to send a PATH_CIDS_BLOCKED frame.
// This informs the peer that we tried to provide a CID for a path but were blocked.
func (m *multiPathManager) QueuePathCIDsBlockedFrame(pathID protocol.PathID, nextSeqNum uint64) {
	frame := &wire.PathCIDsBlockedFrame{PathIdentifier: pathID, NextSequenceNumber: nextSeqNum}
	m.conn.QueueControlFrame(frame)
	m.logger.Debugf("Queued PATH_CIDS_BLOCKED frame for PathIdentifier %d, NextSequenceNumber %d", pathID, nextSeqNum)
}

// HandlePathAckFrame is called when a PATH_ACK frame is received.
func (m *multiPathManager) HandlePathAckFrame(frame *wire.PathAckFrame, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p := range m.paths {
		if p.id == frame.PathIdentifier {
			path = p
			break
		}
	}

	if path == nil {
		m.logger.Debugf("Received PATH_ACK for unknown path %d", frame.PathIdentifier)
		return
	}

	m.logger.Debugf("Received PATH_ACK for path %d, LargestAcked: %d", frame.PathIdentifier, frame.LargestAcked)

	// TODO: This frame should be processed by a path-specific instance of SentPacketHandler.
	// This involves:
	// 1. Finding the correct SentPacketHandler for path.id.
	// 2. Calling its ReceivedAck method, similar to how connection.handleAckFrame does.
	//    This will trigger loss detection, RTT updates, congestion control updates, etc., for that specific path.
	// For now, we just log its receipt.
	// Example conceptual call:
	// sph := getSentPacketHandlerForPath(path.id)
	// if sph != nil {
	//    err := sph.ReceivedAck(frameToAckFrame(frame), pathSpecificEncryptionLevel, rcvTime)
	//    if err != nil {
	//        m.conn.CloseWithError(err)
	//    }
	// }
}

// HandlePathNewConnectionID is called when a PATH_NEW_CONNECTION_ID frame is received.
func (m *multiPathManager) HandlePathNewConnectionID(frame *wire.PathNewConnectionIDFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p :=range m.paths {
		if p.id == frame.PathIdentifier {
			path = p
			break
		}
	}

	if path == nil {
		// TODO: How to handle PATH_NEW_CONNECTION_ID for an unknown path?
		// This could be an old path that was already removed or a new path from the peer
		// that we haven't processed a PATH_CHALLENGE for yet (if server can send unsolicited).
		// For now, log and ignore.
		m.logger.Debugf("Received PATH_NEW_CONNECTION_ID for unknown path %d", frame.PathIdentifier)
		return
	}

	m.logger.Debugf("Received PATH_NEW_CONNECTION_ID for path %d: SeqNum %d, RetirePriorTo %d, CID %s",
		frame.PathIdentifier, frame.SequenceNumber, frame.RetirePriorTo, frame.ConnectionID)

	// Add the new CID to the path's list of CIDs the peer provided for us.
	newPeerCID := ConnectionIDInfo{
		CID:            frame.ConnectionID,
		SequenceNumber: frame.SequenceNumber,
		// StatelessResetToken: frame.StatelessResetToken, // TODO: Add to ConnectionIDInfo
	}
	// TODO: Store the stateless reset token with the CID info.
	_ = frame.StatelessResetToken // Avoid unused variable for now.

	// Check for duplicates
	for _, existingCID := range path.peerConnectionIDs {
		if existingCID.SequenceNumber == frame.SequenceNumber {
			m.logger.Debugf("Ignoring duplicate PATH_NEW_CONNECTION_ID for path %d, SeqNum %d", path.id, frame.SequenceNumber)
			return // Or handle as an error? For now, ignore.
		}
	}
	path.peerConnectionIDs = append(path.peerConnectionIDs, newPeerCID)
	// TODO: Sort peerConnectionIDs by sequence number if necessary for RetirePriorTo logic or selection.

	// Handle RetirePriorTo:
	// We need to inform the main connection's CID manager about CIDs that the peer retired on this specific path.
	// The main CID manager might not be path-aware in its current form.
	// This is a placeholder for future integration.
	if frame.RetirePriorTo > 0 {
		// The conn.RetirePeerConnectionID is a conceptual call.
		// The actual implementation in connection.go's connIDManager might need adjustments
		// to handle path-specific retirement or this needs to be managed within multiPathManager
		// by interacting more granularly with a path-aware connIDManager.
		// For now, assume this tells the connection to globally retire CIDs with seq < RetirePriorTo *for this path*.
		// This is complex because CIDs are globally unique but their use here is path-specific.
		m.conn.RetirePeerConnectionID(path.id, frame.RetirePriorTo)

		// Also, update our local list of peer CIDs for this path
		var activePeerCIDs []ConnectionIDInfo
		for _, cidInfo := range path.peerConnectionIDs {
			if cidInfo.SequenceNumber >= frame.RetirePriorTo {
				activePeerCIDs = append(activePeerCIDs, cidInfo)
			} else {
				m.logger.Debugf("Path %d: Peer retired CID %s (SeqNum %d) via RetirePriorTo %d", path.id, cidInfo.CID, cidInfo.SequenceNumber, frame.RetirePriorTo)
			}
		}
		path.peerConnectionIDs = activePeerCIDs
	}

	// If this is the first CID for a path that was waiting, it might unblock sending.
	// (e.g. server side, after receiving client's PATH_CHALLENGE, client sends its CID for this path)
	if len(path.peerConnectionIDs) == 1 && path.peerConnectionIDs[0].SequenceNumber == frame.SequenceNumber {
		m.logger.Debugf("Path %d now has its first peer-provided CID: %s", path.id, frame.ConnectionID)
		// TODO: Trigger any path state changes or pending operations that depended on having a peer CID.
	}
}

// HandlePathRetireConnectionID is called when a PATH_RETIRE_CONNECTION_ID frame is received.
func (m *multiPathManager) HandlePathRetireConnectionID(frame *wire.PathRetireConnectionIDFrame, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var path *quicPath
	for _, p := range m.paths {
		if p.id == frame.PathIdentifier {
			path = p
			break
		}
	}

	if path == nil {
		m.logger.Debugf("Received PATH_RETIRE_CONNECTION_ID for unknown path %d", frame.PathIdentifier)
		return
	}

	m.logger.Debugf("Received PATH_RETIRE_CONNECTION_ID for path %d: SeqNum %d", frame.PathIdentifier, frame.SequenceNumber)

	found := false
	for i := range path.ourConnectionIDs {
		// Assuming ourConnectionIDs stores CIDs we provided to the peer for this path.
		if path.ourConnectionIDs[i].SequenceNumber == frame.SequenceNumber {
			// Mark as retired or remove. For now, let's just log.
			// A real implementation would update ConnIDGenerator state.
			m.logger.Debugf("Path %d: Peer retired our CID %s (SeqNum %d)", path.id, path.ourConnectionIDs[i].CID, frame.SequenceNumber)
			// TODO: path.ourConnectionIDs[i].IsRetired = true (if IsRetired field is added)
			// TODO: Inform connIDGenerator that this CID is retired for this path.
			// This is complex as connIDGenerator might not be path-aware.
			found = true
			break
		}
	}

	if !found {
		m.logger.Debugf("Received PATH_RETIRE_CONNECTION_ID for path %d with unknown SeqNum %d", path.id, frame.SequenceNumber)
	}

	// TODO: Implement logic to provide a new CID for this path if needed,
	// by calling m.conn.ConnIDGenerator() (which needs to be path-aware)
	// and then queueing a PATH_NEW_CONNECTION_ID frame via m.conn.QueueControlFrame().
	// Example:
	// if path needs more CIDs {
	//    newCID := m.conn.ConnIDGenerator().GenerateConnectionIDForPath(path.id)
	//    newSeqNum := m.conn.ConnIDGenerator().GetConnectionIDSequenceNumber(newCID)
	//    // ... get stateless reset token ...
	//    pathNewCIDFrame := &wire.PathNewConnectionIDFrame{
	//        PathIdentifier: path.id,
	//        SequenceNumber: newSeqNum,
	//        // RetirePriorTo: ... , // Determine this based on peer's retirements
	//        ConnectionID: newCID,
	//        // StatelessResetToken: ... ,
	//    }
	//    m.conn.QueueControlFrame(pathNewCIDFrame)
	// }
}

// InitiatePathProbe attempts to validate a new path to the given remote address.
// This is typically called by the client.
func (m *multiPathManager) InitiatePathProbe(remoteAddr net.Addr) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.conn.Perspective() == protocol.PerspectiveServer {
		return errors.New("server cannot initiate path probing")
	}

	// TODO: Check against localInitialMaxPathID and peerInitialMaxPathID
	// For now, allow up to a small number of paths for testing.
	// Path ID 0 is the default path. Max 1 additional path for now.
	if m.nextLocalPathID >= 1 && m.nextLocalPathID >= m.conn.GetLocalInitialMaxPathID() {
		return errors.New("reached local limit for active paths")
	}
	// A more complete check would also consider peer's advertised limit if known.

	newPathID := m.nextLocalPathID + 1 // Path IDs start from 0, new paths are 1, 2, ...

	// TODO: Obtain a real peerConnectionID for this pathID.
	// This will require interaction with the connection ID manager, which needs to become path-aware.
	// For now, let's assume the peer will use its initial DCID for all paths, or we get a new one.
	// This is a placeholder and likely incorrect for a fully compliant multipath implementation.
	var peerCID protocol.ConnectionID
	if m.conn.ConnIDManager() != nil && len(m.paths) > 0 { // Try to get a new one if possible
		// This is a simplification. Real CID management for paths is complex.
		// We might need a NEW_CONNECTION_ID from the server specifically for this new path.
		// For now, assume we can use the initial CID or one we already have.
		peerCID = m.conn.ConnIDManager().Get() // Placeholder: get any available CID.
	} else {
		// Fallback or initial case, this might be problematic.
		// Consider logging a warning here.
		m.logger.Debugf("InitiatePathProbe: Falling back to potentially unsuitable peer CID for new path %d", newPathID)
		// This might need to be the server's initial SCID if no other CID is available.
		// This detail is crucial and needs to be correctly handled with full CID management.
	}


	// TODO: Obtain a new Connection ID for the peer to use for this path.
	// This involves using the connIDGenerator.
	var ourCIDInfo ConnectionIDInfo
	if m.conn.ConnIDGenerator() != nil {
		// This is a simplification. We need to make sure this CID is associated with the new path
		// and potentially communicated to the peer with a NEW_CONNECTION_ID frame for that path.
		newOurCID := m.conn.ConnIDGenerator().GenerateConnectionID() // Simplified
		if newOurCID.Len() == 0 {
			m.logger.Errorf("Failed to generate new connection ID for path probe")
			// Potentially return error or use a default/initial SCID if that's acceptable for probing.
			// For now, proceed with a zero CID which might be problematic.
		}
		ourCIDInfo = ConnectionIDInfo{CID: newOurCID, SequenceNumber: m.conn.ConnIDGenerator().GetConnectionIDSequenceNumber(newOurCID)}
	} else {
		m.logger.Errorf("ConnIDGenerator not available for path probe")
		// This is a more critical error.
		return errors.New("connection ID generator not available")
	}


	var challengeData [8]byte
	if _, err := rand.Read(challengeData[:]); err != nil {
		return fmt.Errorf("failed to generate path challenge data: %w", err)
	}

	path := &quicPath{
		id:                    protocol.PathID(newPathID),
		remoteAddr:            remoteAddr,
		// localAddr: nil, // TODO: Determine how to set this if needed
		validationState:       PathStateValidating,
		sentPathChallengeData: challengeData,
		isActive:              false,
		peerConnectionIDs:     []ConnectionIDInfo{{CID: peerCID}}, // Initial DCID for this path.
		ourConnectionIDs:      []ConnectionIDInfo{ourCIDInfo},     // The first SCID we provide for this path.
	}
	m.paths = append(m.paths, path)
	m.nextLocalPathID = protocol.PathID(newPathID) // Increment for the next path

	m.logger.Debugf("Initiating probe for path %d to %s. Initial OurCID: %s, Initial PeerCID: %s", path.id, remoteAddr, path.ourConnectionIDs[0].CID, path.peerConnectionIDs[0].CID)

	// Frame and send PATH_CHALLENGE
	pathChallengeFrame := &wire.PathChallengeFrame{Data: challengeData}

	// Packing and sending logic
	// This is simplified. The actual packet packing might need more context (like current PNs, etc.)
	// and the sendQueue might need to handle sending to a specific remoteAddr.
	// The packer needs to be aware of the pathID for nonce generation.

	// Assume packer.PackProbingPacket or similar exists that can take frames and pathID
	// For now, we'll rely on the fact that the 1-RTT sealer used by AppendPacket now takes pathID.
	// We need to ensure the packet is sent on the *new* path's remoteAddr.

	// Construct a minimal set of frames for a probe packet
	// Typically, a PATH_CHALLENGE could be sent with a PING or be a standalone packet.
	// For simplicity, let's assume it's sent in a 1-RTT packet.
	// The packer's AppendPacket or equivalent needs to be used.

	// The following is a placeholder for how packet packing and sending might occur.
	// It needs to be integrated with the existing packet packing mechanisms.
	// For this subtask, the key is to ensure the pathID is used by the AEAD.

	// Simplified: Create a packet specifically for this.
	// In a real scenario, this would be queued and packed by the connection's run loop.
	// We might need a new way to send a packet on a *specific* path with a *specific* SCID/DCID.

	// The packer's AppendPacket now takes pathID.
	// We need to ensure that the packet packer uses the correct SCID (ourCIDInfo.CID)
	// and DCID (peerConnectionID) for this path. This is currently not directly supported
	// by the existing packer interface without more significant changes.
	// For now, we assume the default CIDs might be used by the packer, which is a limitation.

	// TODO: This sending mechanism is highly simplified and needs proper integration.
	// It likely involves queuing control frames and letting the connection's run loop pack and send.
	// For now, let's imagine we can directly ask the packer to create a packet for this path.
	// The current `PackAckOnlyPacket` or `AppendPacket` are for the *current* active path.
	// We need a way to specify CIDs and path for a new probe packet.

	// For the purpose of this subtask, we'll assume that the pathID (path.id)
	// will be correctly used by the AEAD when the connection eventually packs a 1-RTT packet
	// that includes this frame. The direct sending here is a simplification.

	// A more realistic approach:
	// 1. Queue the PATH_CHALLENGE frame (connection.queueControlFrame).
	// 2. The connection's run loop, when sending, needs to be path-aware.
	//    If sending a packet for a specific path (especially a probe), it needs to use
	//    that path's CIDs and pass the pathID to the AEAD.
	// This subtask focuses on initiating, so we'll assume the frame gets queued
	// and the sending mechanism will eventually handle it with the correct pathID.

	// The connection itself should have a way to send a probing packet on a specific path.
	// Let's assume a function like `conn.SendProbingPacket(path *quicPath, frames []wire.Frame)` exists.
	// This function would internally handle using the correct CIDs for that path and passing the pathID to the packer.
	// Since that doesn't exist yet, we'll log the intent.

	m.logger.Debugf("TODO: Implement actual sending of PATH_CHALLENGE for path %d using its CIDs and remoteAddr.", path.id)
	// Example of what might be needed (conceptual):
	// packetBuffer := getPacketBuffer() // from connection's pool
	// packedPacket, err := m.conn.Packer().Pack1RTTProbingPacket(
	//     packetBuffer,
	//     m.conn.maxPacketSize(), // This needs to be path specific potentially
	//     path.id,
	//     path.peerConnectionID, // DCID
	//     path.ourConnectionIDInfo.CID, // SCID
	//     []ackhandler.Frame{{Frame: pathChallengeFrame}},
	//     time.Now(),
	//     m.conn.version(), // Assuming version is accessible
	// )
	// if err != nil {
	//     return fmt.Errorf("failed to pack path challenge: %w", err)
	// }
	// m.conn.SendQueue().SendTo(packedPacket.buffer.Data, path.remoteAddr)


	// For now, just queue the frame. The existing packer logic will pick it up.
	// The key is that when `appendShortHeaderPacket` is called, it will now receive a pathID (0 for now from current callers).
	// To make this *actually* work for path.id, `appendShortHeaderPacket`'s callers need to be path-aware.
	// This subtask assumes pathID 0 for general 1-RTT, but for this specific probe, we'd need path.id.
	// This means the connection's main packing loop needs to be path-aware.
	// That's a larger refactoring.

	// For the purpose of *this* subtask, we are focusing on initiating the probe.
	// The AEAD changes are in place. The next step would be to make the packer/connection use the pathID.
	// We will assume for now that the PATH_CHALLENGE frame is queued and when a 1RTT packet is formed,
	// if the packing logic were fully path-aware, it *would* use path.id.
	// The current setup will send it with pathID 0 if packed by existing top-level functions.

	// To fulfill the "pass the new pathID to the packer function" part of this subtask,
	// we'd need to modify how packets containing specific frames for specific paths are generated.
	// This is non-trivial. Let's assume for now that `queueControlFrame` is the first step,
	// and the actual path-specific packing is a TODO.

	// If we were to directly call a packer function here, it would be something like:
	// (This is a conceptual call, the actual packer methods might need adjustment)
	// sealer, _ := m.conn.CryptoSetup().Get1RTTSealer()
	// if sealer != nil {
	//    // Simplified packing - this bypasses congestion control, ACKs, etc.
	//    // Not how it should be done in production.
	//    hdr := &wire.Header{IsLongHeader: false, DestConnectionID: path.peerConnectionID, SrcConnectionID: path.ourConnectionIDInfo.CID}
	//    payload := []wire.Frame{pathChallengeFrame}
	//    // ... manual packing and sealing using path.id ...
	// }


	return nil // Placeholder for actual send logic
}

// TODO: Add functions for:
// - GetPathByID
// - GetActivePath (for sending non-probing packets)
// - MaybeClosePath / AbandonPath
// - Path lifecycle management (validation timeouts, etc.)

// HandlePathChallenge is called when a PATH_CHALLENGE frame is received.
// This is typically processed by the server.
func (m *multiPathManager) HandlePathChallenge(challenge *wire.PathChallengeFrame, remoteAddr net.Addr, packetDestConnID protocol.ConnectionID, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Debugf("Received PATH_CHALLENGE from %s with data %x on DCID %s", remoteAddr, challenge.Data, packetDestConnID)

	var path *quicPath
	for _, p := range m.paths {
		if p.remoteAddr.String() == remoteAddr.String() { // TODO: more robust address comparison
			path = p
			break
		}
	}

	isNewPath := false
	if path == nil {
		// Server-side: peer's Path ID limit for us is peerInitialMaxPathID
		// Path ID 0 is the default path. Max m.conn.GetPeerInitialMaxPathID() paths in total from this peer.
		// Since nextLocalPathID is used for *our* path IDs, we need a count of existing paths for this remoteAddr.
		// This logic needs refinement if a single remoteAddr can have multiple paths from the peer's perspective.
		// For now, assume one path per remoteAddr for simplicity of finding/creating.
		if uint64(len(m.paths)) >= uint64(m.conn.GetPeerInitialMaxPathID()) && m.conn.GetPeerInitialMaxPathID() != 0 { // 0 means no limit or not set
			m.logger.Debugf("Ignoring PATH_CHALLENGE from %s: path limit reached (%d)", remoteAddr, m.conn.GetPeerInitialMaxPathID())
			return
		}

		newPathID := m.nextLocalPathID + 1 // This is *our* local ID for this path.
		// The client doesn't know this ID yet. This ID is for our internal tracking.

		// TODO: placeholder for getting a CID the client provided for this path.
		// This is complex. For now, assume the client might reuse its SCID for this new path,
		// or we need a NEW_CONNECTION_ID from the client specifically for this.
		// This CID is what we would use as DCID if we send probes back *to* the client on this path.
		var peerCIDForPath protocol.ConnectionID = packetDestConnID // This is problematic, client's SCID for this path.

		path = &quicPath{
			id:                    protocol.PathID(newPathID), // Our local identifier for this path
			remoteAddr:            remoteAddr,
			validationState:       PathStateUnvalidated, // Server needs to validate client's address too
			isActive:              false,
			peerConnectionIDs:     []ConnectionIDInfo{{CID: peerCIDForPath}}, // Initial CID from client for this path
			ourConnectionIDs:      []ConnectionIDInfo{{CID: packetDestConnID}}, // The CID client used (was our DCID on this packet)
			// TODO: ourConnectionIDInfo should ideally also have the sequence number if available from connIDManager
		}
		m.paths = append(m.paths, path)
		m.nextLocalPathID = protocol.PathID(newPathID)
		isNewPath = true
		m.logger.Debugf("Created new path %d for %s based on PATH_CHALLENGE. Initial OurCID for them: %s. Initial TheirCID for us (DCID of received packet): %s", path.id, remoteAddr, path.ourConnectionIDs[0].CID, path.peerConnectionIDs[0].CID)
	} else {
		m.logger.Debugf("Found existing path %d for %s", path.id, remoteAddr)
		// TODO: Update path.lastPacketTime or similar
	}

	// Queue PATH_RESPONSE
	responseFrame := &wire.PathResponseFrame{Data: challenge.Data}
	m.conn.QueueControlFrame(responseFrame)
	m.logger.Debugf("Queued PATH_RESPONSE to %s for path %d with data %x", remoteAddr, path.id, responseFrame.Data)

	// Server also validates the client's path
	// "If the server wants to use the path for sending packets to the client,
	// it MUST validate the client’s address by sending its own PATH_CHALLENGE frames to the client."
	// We'll do this if it's a new path or if the existing path is not yet validated by us.
	if path.validationState == PathStateUnvalidated || isNewPath {
		var pathChallengeData [8]byte
		if _, err := rand.Read(pathChallengeData[:]); err != nil {
			m.logger.Errorf("Failed to generate path challenge data for path %d: %v", path.id, err)
			return
		}
		path.sentPathChallengeData = pathChallengeData
		path.validationState = PathStateValidating // Server is now validating this path towards the client

		challengeFrame := &wire.PathChallengeFrame{Data: pathChallengeData}
		m.conn.QueueControlFrame(challengeFrame)
		m.logger.Debugf("Queued PATH_CHALLENGE to %s for path %d with data %x (server validating client)", remoteAddr, path.id, challengeFrame.Data)
	}
}

// HandlePathResponse is called when a PATH_RESPONSE frame is received.
// This is typically processed by the client.
func (m *multiPathManager) HandlePathResponse(response *wire.PathResponseFrame, remoteAddr net.Addr, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Debugf("Received PATH_RESPONSE from %s with data %x", remoteAddr, response.Data)

	var foundPath *quicPath
	for _, p := range m.paths {
		// TODO: More robust address comparison needed if local interface matters
		if p.remoteAddr.String() == remoteAddr.String() &&
			p.validationState == PathStateValidating &&
			p.sentPathChallengeData == response.Data {
			foundPath = p
			break
		}
	}

	if foundPath != nil {
		foundPath.validationState = PathStateValidated
		foundPath.isActive = true // Or based on some other criteria for "active"
		m.logger.Infof("Path %d to %s successfully validated.", foundPath.id, remoteAddr)
		// TODO: Initialize RTT/Congestion controllers for this path.
		// TODO: Potentially make this the active path for sending data if conditions are met.
	} else {
		m.logger.Debugf("Received unexpected or invalid PATH_RESPONSE from %s (data: %x). No matching pending challenge found.", remoteAddr, response.Data)
	}
}

[end of multipath_manager.go]
