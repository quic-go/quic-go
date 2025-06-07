package quic

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
)

// PathValidationState represents the validation state of a path
type PathValidationState uint8
const (
	PathStateUnvalidated PathValidationState = iota
	PathStateValidating
	PathStateValidated
	PathStateFailed
)

// ConnectionIDInfo stores information about a connection ID
type ConnectionIDInfo struct {
	CID                 protocol.ConnectionID
	SequenceNumber      uint64
	StatelessResetToken protocol.StatelessResetToken
}

type quicPath struct {
	id protocol.PathID
	remoteAddr net.Addr; localAddr  net.Addr
	validationState PathValidationState; sentPathChallengeData [8]byte; isActive bool
	peerConnectionIDs []ConnectionIDInfo
	ourConnectionIDs  []ConnectionIDInfo
	peerAdvertisedStatus PathPeerAdvertisedStatus
	lastPeerPathStatusSeqNum uint64; ourLastPathStatusSeqNum  uint64
	sentPathAbandon bool; rcvdPathAbandon bool; abandonTime time.Time
	rttStats              *utils.RTTStats
	congestionController  congestion.SendAlgorithmWithDebugInfos
	pacer                 *congestion.Pacer
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	packetNumberGenerator *ackhandler.PacketNumberGenerator
	mtuDiscoverer         mtuDiscoverer
}

func (p *quicPath) ID() protocol.PathID { return p.id }
func (p *quicPath) SentPacketHandler() ackhandler.SentPacketHandler { return p.sentPacketHandler }
func (p *quicPath) ReceivedPacketHandler() ackhandler.ReceivedPacketHandler { return p.receivedPacketHandler }
func (p *quicPath) PacketNumberGenerator() *ackhandler.PacketNumberGenerator { return p.packetNumberGenerator }
func (p *quicPath) CongestionController() congestion.SendAlgorithmWithDebugInfos { return p.congestionController }
func (p *quicPath) Pacer() *congestion.Pacer { return p.pacer }
func (p *quicPath) MtuDiscoverer() mtuDiscoverer { return p.mtuDiscoverer }
func (p *quicPath) PeerConnectionID() protocol.ConnectionID {
	if len(p.peerConnectionIDs) > 0 { return p.peerConnectionIDs[len(p.peerConnectionIDs)-1].CID }
	return nil
}
func (p *quicPath) OurConnectionID() protocol.ConnectionID {
	if len(p.ourConnectionIDs) > 0 { return p.ourConnectionIDs[0].CID }
	return nil
}

type multiPathManager struct {
	mutex sync.Mutex
	paths []*quicPath
	nextLocalPathID protocol.PathID
	peerMaxPathIDAdvertised protocol.PathID
	ourMaxPathIDAdvertised  protocol.PathID
	isMultipathActiveOnConn bool // Tracks if the connection decided multipath is active
	logger utils.Logger
	conn   iConnectionFramework
}

type iConnectionFramework interface {
	Perspective() protocol.Perspective
	Packer() packer
	SendQueue() sender
	CloseWithError(error)
	ConnIDGenerator() *ConnectionIDGenerator
	ConnIDManager() *connIDManager
	GetPeerInitialMaxPathID() protocol.PathID
	GetLocalInitialMaxPathID() protocol.PathID
	GetPeerTransportParameters() *wire.TransportParameters
	QueueControlFrame(wire.Frame)
	// RetireOurConnectionIDUsingPeerSeqNum is for when WE want to retire a CID the PEER gave us for a path.
	// ConnIDManager's RetireDestinationConnectionID handles this.
	RetireOurConnectionIDUsingPeerSeqNum(pathID protocol.PathID, peerSeqNum uint64) error
	GetRTTStats() *utils.RTTStats
	Tracer() *logging.ConnectionTracer
	ConfirmHandshake()
	GetInitialMaxDatagramSize() protocol.ByteCount
	GetLogger() utils.Logger
	GetInitialPeerConnectionID() protocol.ConnectionID
	GetInitialOurConnectionID() protocol.ConnectionID
	GetInitialPeerStatelessResetToken() *protocol.StatelessResetToken
	// RetireOurCID is called when PEER retires one of OUR CIDs (typically for Path 0 via standard RETIRE_CONNECTION_ID)
	RetireOurCID(seqNum uint64, rcvTime time.Time) error
	ShouldStartMTUDiscovery() bool
}

func newMultiPathManager(conn iConnectionFramework, logger utils.Logger, isInitiallyActive bool) *multiPathManager {
	mpm := &multiPathManager{
		paths:                   make([]*quicPath, 0, 2),
		nextLocalPathID:         protocol.InitialPathID,
		conn:                    conn,
		logger:                  logger,
		isMultipathActiveOnConn: isInitiallyActive,
	}
	mpm.peerMaxPathIDAdvertised = conn.GetPeerInitialMaxPathID()
	if mpm.peerMaxPathIDAdvertised == protocol.InvalidPathID { mpm.peerMaxPathIDAdvertised = 0 }
	mpm.ourMaxPathIDAdvertised = conn.GetLocalInitialMaxPathID()
	if mpm.ourMaxPathIDAdvertised == protocol.InvalidPathID { mpm.ourMaxPathIDAdvertised = 0 }

	if isInitiallyActive {
		mpm.setupPath0()
	}
	return mpm
}

func (m *multiPathManager) setupPath0() {
	defaultPathID := protocol.InitialPathID
	// Check if path 0 already exists (e.g. if SetMultipathActive is called multiple times)
	for _, p := range m.paths { if p.id == defaultPathID { return } }

	defaultRTTStats := m.conn.GetRTTStats()
	defaultClock := congestion.NewRTTClock()
	initialMaxDatagramSize := m.conn.GetInitialMaxDatagramSize()

	defaultCC := congestion.NewCubicSender(defaultClock, defaultRTTStats, false, m.conn.GetLogger())
	defaultCC.SetMaxDatagramSize(initialMaxDatagramSize)
	defaultPacer := congestion.NewPacer(defaultCC.TimeUntilSend)
	defaultPacer.SetMaxDatagramSize(initialMaxDatagramSize)

	sph, rph := ackhandler.NewAckHandler(
		0, initialMaxDatagramSize, defaultRTTStats, true, true, /*TODO: ECN*/
		defaultCC, defaultPacer, nil, /* mtuDiscoverer for Path 0 */
		m.conn.Perspective(), m.conn.Tracer(), m.logger,
	)

	var initialPeerSRTForPath0 protocol.StatelessResetToken
	if token := m.conn.GetInitialPeerStatelessResetToken(); token != nil { initialPeerSRTForPath0 = *token }
	// TODO: Get SRT for our initial CID for Path 0
	var ourInitialSRTForPath0 protocol.StatelessResetToken


	path0 := &quicPath{
		id:                    defaultPathID,
		validationState:       PathStateValidated, isActive: true,
		rttStats:              defaultRTTStats,
		congestionController:  defaultCC, pacer: defaultPacer,
		sentPacketHandler:     sph, receivedPacketHandler: rph,
		packetNumberGenerator: ackhandler.NewPacketNumberGenerator(0),
		peerConnectionIDs:     []ConnectionIDInfo{{CID: m.conn.GetInitialPeerConnectionID(), SequenceNumber: 0, StatelessResetToken: initialPeerSRTForPath0}},
		ourConnectionIDs:      []ConnectionIDInfo{{CID: m.conn.GetInitialOurConnectionID(), SequenceNumber: 0, StatelessResetToken: ourInitialSRTForPath0}},
	}
	m.paths = append(m.paths, path0)
}


// SetMultipathActive is called by the connection when TPs are exchanged or config changes.
func (m *multiPathManager) SetMultipathActive(isActive bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.isMultipathActiveOnConn == isActive { return }
	m.isMultipathActiveOnConn = isActive
	if isActive {
		foundPath0 := false
		for _, p := range m.paths { if p.id == protocol.InitialPathID { foundPath0 = true; break } }
		if !foundPath0 {
			// Unlock mutex because setupPath0 might call back into conn which might lock itself
			m.mutex.Unlock()
			m.setupPath0()
			m.mutex.Lock() // Re-acquire lock
		}
	} else {
		// TODO: What to do if multipath becomes inactive? Abandon paths?
		m.logger.Debugf("Multipath became inactive. Current paths: %d", len(m.paths))
	}
}
func (m *multiPathManager) UpdatePeerAdvertisedPathLimit(limit protocol.PathID) {
	m.mutex.Lock(); defer m.mutex.Unlock()
	if limit == protocol.InvalidPathID { limit = 0 }
	m.peerMaxPathIDAdvertised = limit
	m.logger.Debugf("Peer advertised path limit updated to: %d", limit)
}

type PathPeerAdvertisedStatus uint8
const ( PathStatusUnknown PathPeerAdvertisedStatus = iota; PathStatusAvailable; PathStatusBackup )
func (m *multiPathManager) GetPeerAdvertisedPathLimit() protocol.PathID { m.mutex.Lock(); defer m.mutex.Unlock(); return m.peerMaxPathIDAdvertised }

// getOrCreatePathForChallenge is a simplified helper. Proper CID management and local address selection are complex.
func (m *multiPathManager) getOrCreatePathForChallenge(remoteAddr net.Addr, packetDestConnID protocol.ConnectionID, rcvTime time.Time) *quicPath {
	m.logger.Debugf("HandlePathChallenge: looking for path for remoteAddr %s", remoteAddr.String())
	for _, p := range m.paths {
		// Simplified address comparison. In reality, consider network interface, port, etc.
		if p.remoteAddr.String() == remoteAddr.String() && p.localAddr.String() == m.conn.LocalAddr().String() {
			m.logger.Debugf("HandlePathChallenge: found existing path %d for address %s", p.id, remoteAddr.String())
			return p
		}
	}

	if m.nextLocalPathID > m.ourMaxPathIDAdvertised && m.ourMaxPathIDAdvertised != 0 {
		m.logger.Infof("HandlePathChallenge: cannot create new path, reached local MaxPathID limit %d (next available: %d)", m.ourMaxPathIDAdvertised, m.nextLocalPathID)
		// TODO: Queue PATHS_BLOCKED frame if appropriate.
		return nil
	}

	localAddr := m.conn.LocalAddr() // This might need to be more specific to the interface that received the challenge.

	newPathID := m.nextLocalPathID
	// Ensure nextLocalPathID does not exceed overall QUIC path ID limits if any.
	// For now, assume simple increment is fine up to ourMaxPathIDAdvertised.
	m.nextLocalPathID++

	m.logger.Debugf("HandlePathChallenge: creating new path %d for remote %s / local %s", newPathID, remoteAddr.String(), localAddr.String())

	rttStats := utils.NewRTTStats()
	// Consider inheriting RTT from the main path or a similar existing path.
	// rttStats.SetInitialRTT(m.conn.GetRTTStats().SmoothedRTT())

	initialMaxDatagramSize := m.conn.GetInitialMaxDatagramSize()
	clock := congestion.NewRTTClock()

	// TODO: Determine ECN capability for the new path. Assume false for now.
	isECNEnabled := false

	cc := congestion.NewCubicSender(clock, rttStats, isECNEnabled, m.conn.GetLogger())
	cc.SetMaxDatagramSize(initialMaxDatagramSize)

	pacer := congestion.NewPacer(cc.TimeUntilSend)
	pacer.SetMaxDatagramSize(initialMaxDatagramSize)

	// Path variable needs to be accessible for mtuDiscoverer creation before SPH/RPH
	path := &quicPath{
		id:                    newPathID,
		remoteAddr:            remoteAddr,
		localAddr:             localAddr,
		validationState:       PathStateUnvalidated,
		isActive:              false,
		rttStats:              rttStats,
		congestionController:  cc,
		pacer:                 pacer,
		packetNumberGenerator: ackhandler.NewPacketNumberGenerator(protocol.InitialPacketNumber),
		// CIDs are set below
	}

	maxPacketSize := protocol.MaxPacketBufferSize
	if peerTPs := m.conn.GetPeerTransportParameters(); peerTPs != nil && peerTPs.MaxUDPPayloadSize > 0 {
		maxPacketSize = peerTPs.MaxUDPPayloadSize
	}
	path.mtuDiscoverer = newMTUDiscoverer(path.rttStats, initialMaxDatagramSize, maxPacketSize, m.conn.Tracer())

	sph, rph := ackhandler.NewAckHandler(
		protocol.InitialPacketNumber,
		initialMaxDatagramSize,
		path.rttStats, // Use path.rttStats
		m.conn.Perspective() == protocol.PerspectiveServer, // isServer
		isECNEnabled,
		path.congestionController, // Use path.congestionController
		path.pacer,               // Use path.pacer
		path.mtuDiscoverer,       // Pass the created mtuDiscoverer
		m.conn.Perspective(),
		m.conn.Tracer(),
		m.conn.GetLogger(),
	)
	path.sentPacketHandler = sph
	path.receivedPacketHandler = rph

	// Assign our CID that the peer used for the challenge to this path.
	// The sequence number for this CID needs to be correctly obtained from connIDGenerator.
	ourCIDSeqNum := m.conn.ConnIDGenerator().GetLeastUnretiredSequenceNumber(newPathID) // Placeholder, might need specific func
	// A new CID should be generated by us for the client to use on this new path.
	// This should be sent via PATH_NEW_CONNECTION_ID.
	// For now, this part is TBD and handled by ConnIDGenerator calls elsewhere.

	// The path struct was already initialized above before MTU discoverer and SPH/RPH
	ourCIDSeqNum := m.conn.ConnIDGenerator().GetLeastUnretiredSequenceNumber(newPathID) // Placeholder
	path.ourConnectionIDs = []ConnectionIDInfo{{CID: packetDestConnID, SequenceNumber: ourCIDSeqNum}}
	// peerConnectionIDs will be populated upon receiving PATH_NEW_CONNECTION_ID from peer for this path.

	// Start is called when path becomes validated and ready for application data. (Moved to HandlePathChallenge)
	// For server handling PATH_CHALLENGE, it will send PATH_RESPONSE and its own challenge.
	// MTU discovery can start once it's ready to send its own challenge.

	m.paths = append(m.paths, path)
	m.logger.Debugf("HandlePathChallenge: New path %d added. Total paths: %d", newPathID, len(m.paths))
	return path
}

func (m *multiPathManager) InitiatePathProbe(remoteAddr net.Addr) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.conn.Perspective() != protocol.PerspectiveClient {
		return errors.New("InitiatePathProbe called by server")
	}

	// Check if a path to this remoteAddr already exists and is validating/validated
	for _, p := range m.paths {
		if p.remoteAddr.String() == remoteAddr.String() && (p.validationState == PathStateValidating || p.validationState == PathStateValidated) {
			m.logger.Debugf("InitiatePathProbe: Path to %s already exists and is validating/validated (Path ID: %d, State: %d)", remoteAddr.String(), p.id, p.validationState)
			return fmt.Errorf("path to %s already exists or is being validated", remoteAddr.String())
		}
	}

	if m.nextLocalPathID > m.ourMaxPathIDAdvertised && m.ourMaxPathIDAdvertised != 0 {
		m.logger.Infof("InitiatePathProbe: Cannot create new path, reached local MaxPathID limit %d", m.ourMaxPathIDAdvertised)
		// TODO: Queue PATHS_BLOCKED frame?
		return errors.New("cannot create new path, reached local MaxPathID limit")
	}

	localAddr := m.conn.LocalAddr() // TODO: More specific local address selection if possible/needed.
	newPathID := m.nextLocalPathID
	m.nextLocalPathID++

	var challengeData [8]byte
	if _, err := rand.Read(challengeData[:]); err != nil {
		return fmt.Errorf("failed to generate random data for PATH_CHALLENGE: %w", err)
	}

	m.logger.Debugf("InitiatePathProbe: Creating new path %d for probing %s from %s. Challenge: %x", newPathID, remoteAddr.String(), localAddr.String(), challengeData)

	// Create a minimal path object. Full components (SPH, CC, etc.) initialized upon PATH_RESPONSE.
	path := &quicPath{
		id:                    newPathID,
		remoteAddr:            remoteAddr,
		localAddr:             localAddr,
		validationState:       PathStateValidating,
		sentPathChallengeData: challengeData, // Store the challenge data we are sending
		isActive:              false,         // Not active for data transfer until validated
		rttStats:              utils.NewRTTStats(), // Basic RTT stats, can be seeded
		// Other fields (congestionController, pacer, sentPacketHandler, receivedPacketHandler, mtuDiscoverer)
		// will be initialized in HandlePathResponse after successful validation.
		// PacketNumberGenerator could be initialized here if needed for probe packet.
		packetNumberGenerator: ackhandler.NewPacketNumberGenerator(protocol.InitialPacketNumber),
	}
	// TODO: CID management for this new path. Client needs to pick a new CID for itself if it's not using the initial one.
	// And it needs to tell the server about it (PATH_NEW_CONNECTION_ID).
	// For now, assume initial CIDs are used or packer handles it.
	// path.ourConnectionIDs = ...
	// path.peerConnectionIDs = ... (server's CID for this path, might be the initial one)

	m.paths = append(m.paths, path)

	// Queue a PATH_CHALLENGE frame.
	// This frame needs to be sent on the new (probing) path.
	// The SendQueue/Packer must be able to handle sending on a path that is still PathStateValidating.
	// This might require special handling in the packer or send queue to use the specified path ID and addresses.
	m.conn.QueueControlFrame(&wire.PathChallengeFrame{Data: challengeData})
	// IMPORTANT: The above QueueControlFrame typically sends on the "primary" path or Path 0.
	// We need a way to associate this frame with the NEW path.
	// This might involve a new method in iConnectionFramework like:
	// QueueControlFrameOnPath(f wire.Frame, pathID protocol.PathID, destinationAddress net.Addr)
	// Or the packer needs to be path-aware for PATH_CHALLENGE/RESPONSE frames.
	// For now, this is a known limitation of the current QueueControlFrame.
	// A workaround could be to use a special packet type for probes that packer handles.
	// Or, the connection's sendPackets loop needs to check for paths in Validating state
	// and send any queued PATH_CHALLENGE frames on them.

	m.logger.Debugf("InitiatePathProbe: Path %d created, PATH_CHALLENGE queued. Total paths: %d", newPathID, len(m.paths))
	return nil
}

func (m *multiPathManager) HandlePathChallenge(challenge *wire.PathChallengeFrame, remoteAddr net.Addr, packetDestConnID protocol.ConnectionID, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.conn.Perspective() != protocol.PerspectiveServer {
		m.logger.Debugf("HandlePathChallenge: Client received PATH_CHALLENGE, ignoring.")
		// Clients do not process PATH_CHALLENGE frames typically, they send them and expect PATH_RESPONSE.
		// Or if they do, it's for a different validation pattern (e.g. peer initiated).
		// For now, per spec, server responds to client's challenge.
		return
	}

	path := m.getOrCreatePathForChallenge(remoteAddr, packetDestConnID, rcvTime)
	if path == nil {
		m.logger.Debugf("HandlePathChallenge: Could not get or create path for %s. Ignoring challenge.", remoteAddr.String())
		return
	}

	// Store received challenge data to be echoed in PATH_RESPONSE
	path.sentPathChallengeData = challenge.Data // Name is from sender's perspective of data
	path.validationState = PathStateValidating

	// Queue PATH_RESPONSE
	m.conn.QueueControlFrame(&wire.PathResponseFrame{Data: challenge.Data})
	m.logger.Debugf("HandlePathChallenge: Queued PATH_RESPONSE for path %d with data %x", path.id, challenge.Data)

	// Server should also send its own PATH_CHALLENGE to validate the path in the other direction (server to client)
	// unless it has already validated this path (e.g. from a previous challenge it sent).
	// This example assumes it sends a challenge if the path is newly 'Validating'.
	if !path.isActive { // Path just created or was not active, server validates its side.
		var pathChallengeData [8]byte
		if _, err := rand.Read(pathChallengeData[:]); err != nil {
			m.logger.Errorf("HandlePathChallenge: Failed to generate random data for PATH_CHALLENGE: %v", err)
			// Decide if to proceed without sending a challenge or mark path as failed.
			// For now, continue and let client challenge us if it wants.
		} else {
			// Store our challenge data to verify response from client later.
			// path.ourChallengeData = pathChallengeData // Need a field for this
			m.conn.QueueControlFrame(&wire.PathChallengeFrame{Data: pathChallengeData})
			m.logger.Debugf("HandlePathChallenge: Queued own PATH_CHALLENGE for path %d with data %x", path.id, pathChallengeData)
		}
	}

	// If the path was newly created and components initialized, start MTU discovery
	if path.mtuDiscoverer != nil && !path.isActive { // Path is new, just got its components.
	    // isActive will be set true once client responds to our challenge or we get other activity.
	    // For now, MTU discovery can start as we are sending our own challenge.
		path.mtuDiscoverer.Start(rcvTime)
		m.logger.Debugf("HandlePathChallenge: Started MTU discovery on new path %d", path.id)

		// Server proactively issues new CIDs for this new path it's trying to validate.
		if m.conn.Perspective() == protocol.PerspectiveServer {
			m.logger.Debugf("Path %d: Server proactively issuing new CIDs upon its own challenge.", path.id)
			for i := 0; i < 2; i++ { // Issue up to 2 CIDs initially
				if err := m.conn.GetConnIDGenerator().GenerateNewConnectionID(path.id, false); err != nil {
					m.logger.Errorf("Path %d: failed to generate initial CID %d for server use: %v", path.id, i+1, err)
					break // Stop if there's an error (e.g., limit reached)
				}
			}
		}
	}
	path.isActive = true // Mark active for sending the response/challenge. Actual validation is ongoing.
}

// getPathForResponseAndValidate is a simplified helper for clients processing PATH_RESPONSE.
func (m *multiPathManager) getPathForResponseAndValidate(challengeData [8]byte, remoteAddr net.Addr, rcvTime time.Time) *quicPath {
	m.logger.Debugf("HandlePathResponse: looking for path matching challenge data %x from %s", challengeData, remoteAddr.String())
	for _, p := range m.paths {
		// Matching remoteAddr and previously sent challengeData.
		if p.remoteAddr.String() == remoteAddr.String() && p.sentPathChallengeData == challengeData {
			if p.validationState == PathStateValidating {
				m.logger.Debugf("HandlePathResponse: found matching path %d in validating state", p.id)
				p.validationState = PathStateValidated
				p.isActive = true // Path is now considered active and validated by peer's response.

				// Initialize components if this path was placeholder from InitiatePathProbe
				if p.sentPacketHandler == nil {
					m.logger.Debugf("HandlePathResponse: Path %d requires full component initialization.", p.id)
					initialMaxDatagramSize := m.conn.GetInitialMaxDatagramSize()
					if p.rttStats == nil { p.rttStats = utils.NewRTTStats() }
					// Optionally seed RTT: p.rttStats.SetInitialRTT(m.conn.GetRTTStats().SmoothedRTT())

					clock := congestion.NewRTTClock()
					isECNEnabled := false // TODO: Determine ECN for this path (e.g., from connection settings)

					cc := congestion.NewCubicSender(clock, p.rttStats, isECNEnabled, m.conn.GetLogger())
					cc.SetMaxDatagramSize(initialMaxDatagramSize)
					p.congestionController = cc

					pacer := congestion.NewPacer(cc.TimeUntilSend)
					pacer.SetMaxDatagramSize(initialMaxDatagramSize)
					p.pacer = pacer

					// MTU Discoverer Initialization (before NewAckHandler)
					maxPacketSize := protocol.MaxPacketBufferSize
					if peerTPs := m.conn.GetPeerTransportParameters(); peerTPs != nil && peerTPs.MaxUDPPayloadSize > 0 {
						maxPacketSize = peerTPs.MaxUDPPayloadSize
					}
					p.mtuDiscoverer = newMTUDiscoverer(p.rttStats, initialMaxDatagramSize, maxPacketSize, m.conn.Tracer())

					sph, rph := ackhandler.NewAckHandler(
						protocol.InitialPacketNumber,
						initialMaxDatagramSize,
						p.rttStats,
						m.conn.Perspective() == protocol.PerspectiveServer, // isServer
						isECNEnabled,
						p.congestionController,
						p.pacer,
						p.mtuDiscoverer, // Pass the created mtuDiscoverer
						m.conn.Perspective(),
						m.conn.Tracer(),
						m.conn.GetLogger(),
					)
					p.sentPacketHandler = sph
					p.receivedPacketHandler = rph
					if p.packetNumberGenerator == nil {
						p.packetNumberGenerator = ackhandler.NewPacketNumberGenerator(protocol.InitialPacketNumber)
					}

					// Start MTU discoverer now that all components are set up
					p.mtuDiscoverer.Start(rcvTime)
					m.logger.Debugf("HandlePathResponse: Started MTU discovery on validated path %d", p.id)

					// Client should also provide a CID for server to use on this path via PATH_NEW_CONNECTION_ID.
					if m.conn.Perspective() == protocol.PerspectiveClient {
						m.logger.Debugf("Path %d: Client proactively issuing new CIDs upon validation.", p.id)
						for i := 0; i < 2; i++ { // Issue up to 2 CIDs initially
							if err := m.conn.GetConnIDGenerator().GenerateNewConnectionID(p.id, false); err != nil {
								m.logger.Errorf("Path %d: failed to generate initial connection ID %d: %v", p.id, i+1, err)
								break // Stop if there's an error (e.g., limit reached)
							}
						}
					}
				} else if p.mtuDiscoverer != nil {
					// If components existed but MTU discoverer somehow wasn't started or needs restart.
					p.mtuDiscoverer.Start(rcvTime)
					// Also issue CIDs if path is re-validated and was missing them,
					// though this scenario is less likely if CIDs were issued on first validation.
					if m.conn.Perspective() == protocol.PerspectiveClient {
						// Check if CIDs are already plentiful for this path before issuing more.
						// This check is simplified; ConnIDGenerator itself handles limits.
						// For simplicity, just try to issue one more if this block is hit.
						if err := m.conn.GetConnIDGenerator().GenerateNewConnectionID(p.id, false); err != nil {
							m.logger.Debugf("Path %d: failed to generate additional CID on re-validation: %v", p.id, err)
						}
					}
				}
				return p
			} else {
				m.logger.Debugf("HandlePathResponse: found matching path %d but its state (%d) is not 'Validating'. Ignoring response.", p.id, p.validationState)
				return nil
			}
		}
	}
	m.logger.Debugf("HandlePathResponse: no path found matching challenge data %x from %s. Might be a late or unexpected response.", challengeData, remoteAddr.String())
	return nil
}


func (m *multiPathManager) HandlePathResponse(response *wire.PathResponseFrame, remoteAddr net.Addr, rcvTime time.Time) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.conn.Perspective() != protocol.PerspectiveClient {
		m.logger.Debugf("HandlePathResponse: Server received PATH_RESPONSE, which is unusual. Ignoring.")
		// Servers send PATH_RESPONSE, they don't typically process them from clients unless the client is also validating the server.
		// This implementation assumes client validates server path via server's PATH_CHALLENGE.
		return
	}

	path := m.getPathForResponseAndValidate(response.Data, remoteAddr, rcvTime)
	if path == nil {
		m.logger.Debugf("HandlePathResponse: Path not validated or found for response data %x from %s. Ignoring.", response.Data, remoteAddr.String())
		return
	}

	m.logger.Infof("HandlePathResponse: Path %d to %s successfully validated.", path.id, remoteAddr.String())
	// Path is now active and validated. MTU discovery started within getPathForResponseAndValidate if path was new.
	// Application can now potentially use this path.
	// TODO: Signal to connection/application that a new path is available and validated.
}
func (m *multiPathManager) HandlePathAvailable(frame *wire.PathAvailableFrame) { /* ... */ }
func (m *multiPathManager) HandlePathBackup(frame *wire.PathBackupFrame) { /* ... */ }
func (m *multiPathManager) SignalPathAvailable(pathID protocol.PathID) error { /* ... */ return nil }
func (m *multiPathManager) SignalPathBackup(pathID protocol.PathID) error    { /* ... */ return nil }

func (m *multiPathManager) HandlePathAbandon(frame *wire.PathAbandonFrame, rcvTime time.Time) {
	m.mutex.Lock(); defer m.mutex.Unlock()
	var path *quicPath; for _, p := range m.paths { if p.id == frame.PathIdentifier { path = p; break } }
	if path == nil || path.rcvdPathAbandon { return }
	path.rcvdPathAbandon = true; path.isActive = false
	if path.abandonTime.IsZero() { path.abandonTime = rcvTime }
	for _, cidInfo := range path.peerConnectionIDs {
		if err := m.conn.RetireOurConnectionIDUsingPeerSeqNum(path.id, cidInfo.SequenceNumber); err != nil {
			m.logger.Errorf("Error retiring peer's CID seq %d for path %d on abandon: %v", cidInfo.SequenceNumber, path.id, err)
		}
	}
	// TODO: Retire our CIDs for this path via ConnIDGenerator
	if !path.sentPathAbandon {
		path.sentPathAbandon = true
		m.conn.QueueControlFrame(&wire.PathAbandonFrame{PathIdentifier: frame.PathIdentifier, ErrorCode: uint64(qerr.NoError)})
	}
	path.validationState = PathStateFailed; m.logger.Infof("Path %d abandoned by peer.", path.id)
}
func (m *multiPathManager) AbandonPath(pathID protocol.PathID, appErrorCode protocol.ApplicationErrorCode) error {
	m.mutex.Lock(); defer m.mutex.Unlock()
	var path *quicPath;
	for _, p := range m.paths { if p.id == pathID { path = p; break } }
	if path == nil { return fmt.Errorf("cannot abandon unknown path %d", pathID) }
	if path.sentPathAbandon { return nil }
	path.sentPathAbandon = true; path.isActive = false
	if path.abandonTime.IsZero() { path.abandonTime = time.Now() }
	m.conn.QueueControlFrame(&wire.PathAbandonFrame{PathIdentifier: path.id, ErrorCode: uint64(appErrorCode)})
	for _, cidInfo := range path.peerConnectionIDs {
		if err := m.conn.RetireOurConnectionIDUsingPeerSeqNum(path.id, cidInfo.SequenceNumber); err != nil {
			m.logger.Errorf("Error retiring peer's CID seq %d for path %d on local abandon: %v", cidInfo.SequenceNumber, path.id, err)
		}
	}
	// TODO: Retire our CIDs for this path via ConnIDGenerator
	path.validationState = PathStateFailed; m.logger.Infof("Path %d abandoned by us.", path.id)
	return nil
}

func (m *multiPathManager) GetLargestPTO() time.Duration { /* ... */
	m.mutex.Lock(); defer m.mutex.Unlock()
	if m.conn == nil || m.conn.GetRTTStats() == nil { return protocol.DefaultMaxAckDelay * 2 }
	mainConnPTO := m.conn.GetRTTStats().PTO(true); largestPTO := mainConnPTO
	for _, p := range m.paths { if p.isActive && p.validationState == PathStateValidated && p.rttStats != nil { pathPTO := p.rttStats.PTO(true); if pathPTO > largestPTO { largestPTO = pathPTO } } }
	return largestPTO
}
func (m *multiPathManager) GetPathForSending(pathID protocol.PathID) *quicPath { /* ... */
	m.mutex.Lock(); defer m.mutex.Unlock()
	for _, p := range m.paths { if p.id == pathID { if p.isActive && p.validationState == PathStateValidated && p.sentPacketHandler != nil /* Ensure ready */ { return p }; return nil } }
	return nil
}
func (m *multiPathManager) GetActiveValidatedPaths() []*quicPath { /* ... */
	m.mutex.Lock(); defer m.mutex.Unlock()
	activePaths := make([]*quicPath, 0, len(m.paths))
	for _, p := range m.paths { if p.isActive && p.validationState == PathStateValidated && p.sentPacketHandler != nil { activePaths = append(activePaths, p) } }
	return activePaths
}
func (m *multiPathManager) HandleMaxPathID(frame *wire.MaxPathIDFrame) { /* ... (as before) ... */ }
func (m *multiPathManager) HandlePathsBlocked(frame *wire.PathsBlockedFrame) { /* ... (as before) ... */ }

func (m *multiPathManager) HandlePathCIDsBlocked(frame *wire.PathCIDsBlockedFrame) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.conn == nil || m.conn.GetConnIDGenerator() == nil {
		return
	}

	// Validate PathIdentifier
	// Path 0 is always valid. Other paths up to what we advertised.
	ourMaxPathID := protocol.PathID(0)
	if cg := m.conn.GetConnIDGenerator(); cg != nil && cg.getOurMaxPathIDFunc != nil { // Check if ConnIDGenerator can provide this
		ourMaxPathID = cg.getOurMaxPathIDFunc()
	} else if m.ourMaxPathIDAdvertised != protocol.InvalidPathID { // Fallback to MPM's view
		ourMaxPathID = m.ourMaxPathIDAdvertised
	}

	if frame.PathIdentifier > ourMaxPathID && frame.PathIdentifier != protocol.InitialPathID {
		m.logger.Debugf("Received PATH_CIDS_BLOCKED for invalid PathIdentifier %d (our MAX_PATH_ID is %d)", frame.PathIdentifier, ourMaxPathID)
		// Optionally send an error. For now, just ignore.
		return
	}

	// Check if path exists, though ConnIDGenerator.GenerateNewConnectionID will also check path validity.
	var pathExists bool
	for _, p := range m.paths {
		if p.id == frame.PathIdentifier {
			pathExists = true
			break
		}
	}
	if !pathExists && frame.PathIdentifier != protocol.InitialPathID { // Path 0 might not be explicitly in m.paths if MPM inactive initially
		m.logger.Debugf("Received PATH_CIDS_BLOCKED for non-existent path %d", frame.PathIdentifier)
		// This could be an error, or we could try to generate a CID for it anyway if pathID is valid.
		// ConnIDGenerator will create path state if it's valid & new.
	}

	m.logger.Debugf("Received PATH_CIDS_BLOCKED for path %d. Generating a new CID.", frame.PathIdentifier)
	// The `retirePriorToOldCIDs` boolean is set to `false` as per subtask instruction.
	// This means we won't aggressively retire older CIDs on this path unless the generator's internal logic decides to.
	if err := m.conn.GetConnIDGenerator().GenerateNewConnectionID(frame.PathIdentifier, false); err != nil {
		m.logger.Errorf("Failed to generate new CID for path %d in response to PATH_CIDS_BLOCKED: %v", frame.PathIdentifier, err)
	} else {
		m.logger.Debugf("Successfully generated new CID for path %d in response to PATH_CIDS_BLOCKED.", frame.PathIdentifier)
	}
}

func (m *multiPathManager) QueueMaxPathIDFrame(maxPathID protocol.PathID) { /* ... (as before) ... */ }
func (m *multiPathManager) QueuePathsBlockedFrame() { /* ... (as before) ... */ }
func (m *multiPathManager) QueuePathCIDsBlockedFrame(pathID protocol.PathID, nextSeqNum uint64) { /* ... (as before) ... */ }
func (m *multiPathManager) HandlePathAckFrame(frame *wire.PathAckFrame, rcvTime time.Time) { /* ... (as before) ... */ }

func (m *multiPathManager) HandleStandardNewConnectionID(frame *wire.NewConnectionIDFrame) error {
	if m.conn.GetConnIDManager() == nil { return errors.New("connIDManager not available") }
	pathFrame := &wire.PathNewConnectionIDFrame{ PathIdentifier: protocol.InitialPathID, SequenceNumber: frame.SequenceNumber, RetirePriorTo: frame.RetirePriorTo, ConnectionID: frame.ConnectionID, StatelessResetToken: frame.StatelessResetToken }
	return m.conn.GetConnIDManager().Add(pathFrame)
}
func (m *multiPathManager) HandleStandardRetireConnectionID(frame *wire.RetireConnectionIDFrame, rcvTime time.Time) error {
	if m.conn.ConnIDGenerator() == nil { return errors.New("connIDGenerator not available") }
	m.logger.Debugf("MultipathManager: Standard RETIRE_CONNECTION_ID for SeqNum %d (Path 0 implicitly)", frame.SequenceNumber)
	return m.conn.RetireOurCID(frame.SequenceNumber, rcvTime) // This calls ConnIDGenerator.Retire for Path 0
}
func (m *multiPathManager) HandlePathNewConnectionID(frame *wire.PathNewConnectionIDFrame) {
	if err := m.conn.GetConnIDManager().Add(frame); err != nil {
		m.logger.Errorf("Error adding PATH_NEW_CONNECTION_ID for path %d: %v", frame.PathIdentifier, err)
	}
}
func (m *multiPathManager) HandlePathRetireConnectionID(frame *wire.PathRetireConnectionIDFrame, rcvTime time.Time) {
	m.logger.Debugf("MultipathManager: Peer retiring our CID with SeqNum %d on Path %d.", frame.SequenceNumber, frame.PathIdentifier)
	err := m.conn.GetConnIDGenerator().Retire(frame.PathIdentifier, frame.SequenceNumber, rcvTime.Add(defaultRetireCIDGracePeriod))
	if err != nil {
		m.logger.Errorf("Error retiring our CID for path %d, seq %d: %v", frame.PathIdentifier, frame.SequenceNumber, err)
		return // If retirement failed, don't proceed to potentially issue a new one.
	}

	// After successful retirement, check if we need to replenish CIDs for this path.
	// Define a minimum threshold for active CIDs we want the peer to have for any path.
	const defaultMinOurActiveCIDsForPath = 2 // TODO: Make this configurable if needed.

	activeCount := m.conn.GetConnIDGenerator().GetActiveCIDCount(frame.PathIdentifier)
	if activeCount < defaultMinOurActiveCIDsForPath {
		m.logger.Debugf("Path %d: Active CID count (%d) fell below threshold (%d) after peer retired CID. Issuing a new one.",
			frame.PathIdentifier, activeCount, defaultMinOurActiveCIDsForPath)
		// The `retirePriorToOldCIDs` boolean is set to `false` here, as we are replenishing,
		// not necessarily trying to force retirement of others unless ConnIDGenerator's limit logic kicks in.
		if genErr := m.conn.GetConnIDGenerator().GenerateNewConnectionID(frame.PathIdentifier, false); genErr != nil {
			m.logger.Errorf("Path %d: Failed to issue new CID after retirement reduced active count: %v", frame.PathIdentifier, genErr)
		} else {
			m.logger.Debugf("Path %d: Successfully issued new CID to replenish active CIDs.", frame.PathIdentifier)
		}
	}
}

[end of multipath_manager.go]
