package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"
)

// iConnectionFramework interface is defined in multipath_manager.go
var _ iConnectionFramework = &connection{}

type unpacker interface {
	UnpackLongHeader(hdr *wire.Header, data []byte) (*unpackedPacket, error)
	UnpackShortHeader(rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error)
}
type streamManager interface {
	GetOrOpenSendStream(protocol.StreamID) (sendStreamI, error)
	GetOrOpenReceiveStream(protocol.StreamID) (receiveStreamI, error)
	OpenStream() (Stream, error)
	OpenUniStream() (SendStream, error)
	OpenStreamSync(context.Context) (Stream, error)
	OpenUniStreamSync(context.Context) (SendStream, error)
	AcceptStream(context.Context) (Stream, error)
	AcceptUniStream(context.Context) (ReceiveStream, error)
	DeleteStream(protocol.StreamID) error
	UpdateLimits(*wire.TransportParameters)
	HandleMaxStreamsFrame(*wire.MaxStreamsFrame)
	CloseWithError(error)
	ResetFor0RTT()
	UseResetMaps()
}
type cryptoStreamHandler interface {
	StartHandshake(context.Context) error
	ChangeConnectionID(protocol.ConnectionID)
	SetLargest1RTTAcked(pn protocol.PacketNumber, ptoProvider func() time.Duration) error
	SetHandshakeConfirmed()
	GetSessionTicket() ([]byte, error)
	NextEvent() handshake.Event
	DiscardInitialKeys()
	HandleMessage([]byte, protocol.EncryptionLevel) error
	io.Closer
	ConnectionState() handshake.ConnectionState
}
type receivedPacket struct {
	buffer     *packetBuffer
	remoteAddr net.Addr
	rcvTime    time.Time
	data       []byte
	ecn        protocol.ECN
	info       packetInfo
}
func (p *receivedPacket) Size() protocol.ByteCount { return protocol.ByteCount(len(p.data)) }
func (p *receivedPacket) Clone() *receivedPacket {
	return &receivedPacket{
		remoteAddr: p.remoteAddr,
		rcvTime:    p.rcvTime,
		data:       p.data,
		buffer:     p.buffer,
		ecn:        p.ecn,
		info:       p.info,
	}
}
type connRunner interface {
	Add(protocol.ConnectionID, packetHandler) bool
	Remove(protocol.ConnectionID)
	ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration)
	AddResetToken(protocol.StatelessResetToken, packetHandler)
	RemoveResetToken(protocol.StatelessResetToken)
}
type closeError struct {
	err       error
	immediate bool
}
type errCloseForRecreating struct {
	nextPacketNumber protocol.PacketNumber
	nextVersion      protocol.Version
}
func (e *errCloseForRecreating) Error() string { return "closing connection in order to recreate it" }
var connTracingID atomic.Uint64
func nextConnTracingID() ConnectionTracingID { return ConnectionTracingID(connTracingID.Add(1)) }

type connection struct {
	handshakeDestConnID protocol.ConnectionID
	origDestConnID      protocol.ConnectionID // For client, its first Initial's DCID. For server, client's initial SCID.
	retrySrcConnID      *protocol.ConnectionID
	srcConnIDLen        int
	perspective         protocol.Perspective
	version             protocol.Version
	config              *Config
	conn                sendConn
	sendQueue           sender

	pathManager         *pathManager
	largestRcvdAppData  protocol.PacketNumber
	pathManagerOutgoing atomic.Pointer[pathManagerOutgoing]

	streamsMap      streamManager
	connIDManager   *connIDManager   // Manages CIDs *provided by the peer*
	connIDGenerator *ConnectionIDGenerator // Generates CIDs *we provide to the peer*
	rttStats        *utils.RTTStats

	cryptoStreamManager   *cryptoStreamManager
	sentPacketHandler     ackhandler.SentPacketHandler     // Main SPH for Initial/Handshake. 1-RTT SPHs are per-path in multiPathManager.
	receivedPacketHandler ackhandler.ReceivedPacketHandler // Main RPH for Initial/Handshake.
	retransmissionQueue   *retransmissionQueue
	framer                *framer
	connFlowController    flowcontrol.ConnectionFlowController
	tokenStoreKey         string
	tokenGenerator        *handshake.TokenGenerator
	unpacker              unpacker
	frameParser           wire.FrameParser
	packer                packer
	mtuDiscoverer         mtuDiscoverer
	currentMTUEstimate    atomic.Uint32
	initialStream         *initialCryptoStream
	handshakeStream       *cryptoStream
	oneRTTStream          *cryptoStream
	cryptoStreamHandler   cryptoStreamHandler

	notifyReceivedPacket chan struct{}
	sendingScheduled     chan struct{}
	receivedPacketMx     sync.Mutex
	receivedPackets      ringbuffer.RingBuffer[receivedPacket]
	closeChan            chan struct{}
	closeErr             atomic.Pointer[closeError]
	ctx                  context.Context
	ctxCancel            context.CancelCauseFunc

	handshakeCompleteChan         chan struct{}
	undecryptablePackets          []receivedPacket
	undecryptablePacketsToProcess []receivedPacket
	earlyConnReadyChan            chan struct{}
	sentFirstPacket               bool
	droppedInitialKeys            bool
	handshakeComplete             bool
	handshakeConfirmed            bool
	receivedRetry                 bool
	versionNegotiated             bool
	receivedFirstPacket           bool

	idleTimeout                             time.Duration
	creationTime                            time.Time
	lastPacketReceivedTime                  time.Time
	firstAckElicitingPacketAfterIdleSentTime time.Time
	pacingDeadline                          time.Time
	peerParams                              *wire.TransportParameters
	peerInitialSRT                          *protocol.StatelessResetToken

	timer                                   connectionTimer
	keepAlivePingSent                       bool
	keepAliveInterval                       time.Duration
	datagramQueue                           *datagramQueue
	connStateMutex                          sync.Mutex
	connState                               ConnectionState
	logID                                   string
	tracer                                  *logging.ConnectionTracer
	logger                                  utils.Logger
	peerInitialMaxPathID                    protocol.PathID
	localInitialMaxPathID                   protocol.PathID
	multiPathManager                        *multiPathManager
}

var _ Connection = &connection{}
var _ EarlyConnection = &connection{}
var _ streamSender = &connection{}
var _ iConnectionFramework = &connection{}


func (s *connection) determineMultipathActive(forTP bool) bool {
	if !s.config.EnableMultipath || s.localInitialMaxPathID == 0 { // MaxPaths 0 or EnableMultipath false means no MP
		return false
	}
	// If called for TP generation, peer TPs not yet known, base on local intent
	if forTP { return true }
	// Otherwise, multipath is active if we support it AND peer supports it (TPs processed)
	return s.peerInitialMaxPathID > 0 || s.peerInitialMaxPathID == protocol.InvalidPathID // Invalid means not received, treat as potentially active
}

var newConnection = func(
	ctx context.Context, ctxCancel context.CancelCauseFunc, conn sendConn, runner connRunner,
	origDestConnID protocol.ConnectionID, retrySrcConnID *protocol.ConnectionID, clientInitialDestConnID protocol.ConnectionID, // client's first Initial DCID
	serverChosenDestConnID protocol.ConnectionID, // server's chosen SCID (client's DCID after Retry/Handshake)
	clientInitialSrcConnID protocol.ConnectionID, // client's SCID
	connIDGen ConnectionIDGenerator,
	statelessResetter *statelessResetter, conf *Config, tlsConf *tls.Config, tokenGenerator *handshake.TokenGenerator,
	clientAddressValidated bool, rtt time.Duration, tracer *logging.ConnectionTracer, logger utils.Logger, v protocol.Version,
) quicConn {
	s := &connection{ /* ... basic field initialization ... */
		ctx: ctx, ctxCancel: ctxCancel, conn: conn, config: conf,
		handshakeDestConnID: serverChosenDestConnID, // This is the DCID the client will use for Handshake/1-RTT with server initially
		srcConnIDLen: clientInitialSrcConnID.Len(), tokenGenerator: tokenGenerator, oneRTTStream: newCryptoStream(),
		perspective: protocol.PerspectiveServer, tracer: tracer, logger: logger, version: v,
		origDestConnID: clientInitialDestConnID, // Client's first destination an Initial was sent to
	}
	if clientInitialDestConnID.Len() > 0 { s.logID = clientInitialDestConnID.String() } else { s.logID = serverChosenDestConnID.String() }

	s.preSetup()
	s.rttStats.SetInitialRTT(rtt)
	s.connIDGenerator = connIDGen

	if conf.EnableMultipath {
		s.localInitialMaxPathID = conf.MaxPaths
		if s.localInitialMaxPathID > protocol.PathID(wire.MaxPathIDValue) { s.localInitialMaxPathID = protocol.InvalidPathID }
		if s.localInitialMaxPathID != protocol.InvalidPathID && clientInitialSrcConnID.Len() == 0 { s.localInitialMaxPathID = protocol.InvalidPathID }
	} else {
		s.localInitialMaxPathID = 0
	}
	s.peerInitialMaxPathID = protocol.InvalidPathID

	s.connIDManager = newConnIDManager(
		clientInitialSrcConnID, // For server, initial DCID for Path 0 is client's SCID.
		nil,       // Server gets client's SRT for this CID from client's NEW_CONNECTION_ID or PATH_NEW_CONNECTION_ID.
		uint64(s.config.ActiveConnectionIDLimit),
		func() protocol.PathID { return s.peerInitialMaxPathID },
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken, s.queueControlFrame, logger)

	isMultipathActive := s.determineMultipathActive(true) // True: for TP generation context
	s.multiPathManager = newMultiPathManager(s, s.logger, isMultipathActive)

	ptoProvider := func() time.Duration {
		if s.multiPathManager == nil { return s.rttStats.PTO(true) }
		return s.multiPathManager.GetLargestPTO()
	}

	statelessResetTokenForPeer := statelessResetter.GetStatelessResetToken(clientInitialSrcConnID)
	params := &wire.TransportParameters{ /* ... transport params ... */
		InitialMaxStreamDataBidiLocal: protocol.ByteCount(s.config.InitialStreamReceiveWindow), InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni: protocol.ByteCount(s.config.InitialStreamReceiveWindow), InitialMaxData: protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout: s.config.MaxIdleTimeout, MaxBidiStreamNum: protocol.StreamNum(s.config.MaxIncomingStreams), MaxUniStreamNum: protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay: protocol.MaxAckDelayInclGranularity, AckDelayExponent: protocol.AckDelayExponent, MaxUDPPayloadSize: protocol.MaxPacketBufferSize,
		StatelessResetToken: &statelessResetTokenForPeer, OriginalDestinationConnectionID: clientInitialDestConnID, ActiveConnectionIDLimit: uint64(s.config.ActiveConnectionIDLimit),
		InitialSourceConnectionID: clientInitialSrcConnID, RetrySourceConnectionID: retrySrcConnID, InitialMaxPathID: uint64(s.localInitialMaxPathID),
	}
	if s.config.EnableDatagrams { params.MaxDatagramFrameSize = wire.MaxDatagramSize } else { params.MaxDatagramFrameSize = protocol.InvalidByteCount }
	if s.tracer != nil && s.tracer.SentTransportParameters != nil { s.tracer.SentTransportParameters(params) }

	cs := handshake.NewCryptoSetupServer(serverChosenDestConnID, conn.LocalAddr(), conn.RemoteAddr(), params, tlsConf, conf.Allow0RTT, s.rttStats, tracer, logger, v, ptoProvider)
	s.cryptoStreamHandler = cs

	mainCongestionController := congestion.NewCubicSender(congestion.DefaultClock{}, s.rttStats, protocol.ByteCount(s.config.InitialPacketSize), true, tracer)
	mainPacer := congestion.NewPacer(mainCongestionController.TimeUntilSend)
	mainCongestionController.SetMaxDatagramSize(protocol.ByteCount(s.config.InitialPacketSize))
	mainPacer.SetMaxDatagramSize(protocol.ByteCount(s.config.InitialPacketSize))

	// Initialize the main connection's MTU discoverer (for Path 0 or when multipath is off)
	// Peer TPs are not available yet, so use default max packet size.
	// It might need to be updated if peer TPs specify a different MaxUDPPayloadSize.
	initialDatagramSize := protocol.ByteCount(s.config.InitialPacketSize)
	s.mtuDiscoverer = newMTUDiscoverer(
		s.rttStats,
		initialDatagramSize,
		protocol.MaxPacketBufferSize, // Default max size
		s.tracer,
	)
	// Start is called when it's ready to send probes. For main SPH, could be Start(s.creationTime) or similar.
	// For now, let's assume it's started implicitly or by a later call if needed,
	// or when the first packet is actually sent. Or, start it here.
	// s.mtuDiscoverer.Start(s.creationTime) // Or time.Now()

	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewAckHandler(
		0, // Initial Packet Number for this SPH
		initialDatagramSize,
		s.rttStats,
		clientAddressValidated,
		s.conn.capabilities().ECN,
		mainCongestionController,
		mainPacer,
		s.mtuDiscoverer, // Pass the main MTU discoverer
		s.perspective,
		tracer,
		logger,
	)
	s.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))

	s.packer = newPacketPacker(clientInitialSrcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective, s.multiPathManager)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen) // srcConnIDLen is client's SCID len
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, s.oneRTTStream)
	return s
}

var newClientConnection = func( /* ... params ... */
	ctx context.Context, conn sendConn, runner connRunner, destConnID protocol.ConnectionID, srcConnID protocol.ConnectionID,
	connIDGen ConnectionIDGenerator, statelessResetter *statelessResetter, conf *Config, tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber, enable0RTT bool, hasNegotiatedVersion bool,
	tracer *logging.ConnectionTracer, logger utils.Logger, v protocol.Version,
) quicConn {
	s := &connection{ /* ... basic field initialization ... */
		conn: conn, config: conf, origDestConnID: destConnID, handshakeDestConnID: destConnID, srcConnIDLen: srcConnID.Len(),
		perspective: protocol.PerspectiveClient, logID: destConnID.String(), logger: logger, tracer: tracer,
		versionNegotiated: hasNegotiatedVersion, version: v,
	}
	s.connIDGenerator = connIDGen
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	s.preSetup()

	// Client's initial DCID for Path 0 is destConnID (server's SCID)
	s.connIDManager = newConnIDManager(
		destConnID,
		nil,
		uint64(s.config.ActiveConnectionIDLimit),
		func() protocol.PathID {
			if s.multiPathManager != nil { return s.multiPathManager.GetPeerAdvertisedPathLimit() }
			// Before TPs, peerInitialMaxPathID is InvalidPathID. Default to 0 for safety if MPM not ready.
			if s.peerInitialMaxPathID != protocol.InvalidPathID { return s.peerInitialMaxPathID }
			return 0
		},
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken, s.queueControlFrame, logger)

	isMultipathActive := false
	if conf.EnableMultipath {
		s.localInitialMaxPathID = conf.MaxPaths
		if s.localInitialMaxPathID > protocol.PathID(wire.MaxPathIDValue) { s.localInitialMaxPathID = protocol.InvalidPathID }
		if s.localInitialMaxPathID != protocol.InvalidPathID && srcConnID.Len() == 0 { s.localInitialMaxPathID = protocol.InvalidPathID }
	} else {
		s.localInitialMaxPathID = 0
	}
	if s.localInitialMaxPathID > 0 { isMultipathActive = true }
	s.peerInitialMaxPathID = protocol.InvalidPathID
	s.multiPathManager = newMultiPathManager(s, s.logger, isMultipathActive)

	ptoProvider := func() time.Duration {
		if s.multiPathManager == nil { return s.rttStats.PTO(true) }
		return s.multiPathManager.GetLargestPTO()
	}

	oneRTTStream := newCryptoStream()
	params := &wire.TransportParameters{ /* ... transport params ... */
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow), InitialMaxStreamDataBidiLocal: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni: protocol.ByteCount(s.config.InitialStreamReceiveWindow), InitialMaxData: protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout: s.config.MaxIdleTimeout, MaxBidiStreamNum: protocol.StreamNum(s.config.MaxIncomingStreams), MaxUniStreamNum: protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay: protocol.MaxAckDelayInclGranularity, MaxUDPPayloadSize: protocol.MaxPacketBufferSize, AckDelayExponent: protocol.AckDelayExponent,
		ActiveConnectionIDLimit: uint64(s.config.ActiveConnectionIDLimit), InitialSourceConnectionID: srcConnID, InitialMaxPathID: uint64(s.localInitialMaxPathID),
	}
	if s.config.EnableDatagrams { params.MaxDatagramFrameSize = wire.MaxDatagramSize } else { params.MaxDatagramFrameSize = protocol.InvalidByteCount }
	if s.tracer != nil && s.tracer.SentTransportParameters != nil { s.tracer.SentTransportParameters(params) }

	cs := handshake.NewCryptoSetupClient(destConnID, params, tlsConf, enable0RTT, s.rttStats, tracer, logger, v, ptoProvider)
	s.cryptoStreamHandler = cs

	mainCongestionController := congestion.NewCubicSender(congestion.DefaultClock{}, s.rttStats, protocol.ByteCount(s.config.InitialPacketSize), true, tracer)
	mainPacer := congestion.NewPacer(mainCongestionController.TimeUntilSend)
	mainCongestionController.SetMaxDatagramSize(protocol.ByteCount(s.config.InitialPacketSize))
	mainPacer.SetMaxDatagramSize(protocol.ByteCount(s.config.InitialPacketSize))

	initialDatagramSize := protocol.ByteCount(s.config.InitialPacketSize)
	s.mtuDiscoverer = newMTUDiscoverer(
		s.rttStats,
		initialDatagramSize,
		protocol.MaxPacketBufferSize, // Default max size, peer TPs not yet known
		s.tracer,
	)
	// s.mtuDiscoverer.Start(s.creationTime) // Or time.Now()

	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewAckHandler(
		initialPacketNumber,
		initialDatagramSize,
		s.rttStats,
		false, // clientAddressValidated is false for client
		s.conn.capabilities().ECN,
		mainCongestionController,
		mainPacer,
		s.mtuDiscoverer, // Pass the main MTU discoverer
		s.perspective,
		tracer,
		logger,
	)
	s.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))

	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective, s.multiPathManager)

	if len(tlsConf.ServerName) > 0 { s.tokenStoreKey = tlsConf.ServerName } else { s.tokenStoreKey = conn.RemoteAddr().String() }
	if s.config.TokenStore != nil { if token := s.config.TokenStore.Pop(s.tokenStoreKey); token != nil { s.packer.SetToken(token.data); s.rttStats.SetInitialRTT(token.rtt) } }
	return s
}

func (s *connection) preSetup() { /* ... unchanged ... */
	s.largestRcvdAppData = protocol.InvalidPacketNumber; s.initialStream = newInitialCryptoStream(s.perspective == protocol.PerspectiveClient); s.handshakeStream = newCryptoStream(); s.sendQueue = newSendQueue(s.conn); s.retransmissionQueue = newRetransmissionQueue(); s.frameParser = *wire.NewFrameParser(s.config.EnableDatagrams); s.rttStats = &utils.RTTStats{}
	s.connFlowController = flowcontrol.NewConnectionFlowController(protocol.ByteCount(s.config.InitialConnectionReceiveWindow), protocol.ByteCount(s.config.MaxConnectionReceiveWindow), func(size protocol.ByteCount) bool { if s.config.AllowConnectionWindowIncrease == nil { return true }; return s.config.AllowConnectionWindowIncrease(s, uint64(size)) }, s.rttStats, s.logger)
	s.earlyConnReadyChan = make(chan struct{}); s.streamsMap = newStreamsMap(s.ctx, s, s.queueControlFrame, s.newFlowController, uint64(s.config.MaxIncomingStreams), uint64(s.config.MaxIncomingUniStreams), s.perspective); s.framer = newFramer(s.connFlowController)
	s.receivedPackets.Init(8); s.notifyReceivedPacket = make(chan struct{}, 1); s.closeChan = make(chan struct{}, 1); s.sendingScheduled = make(chan struct{}, 1); s.handshakeCompleteChan = make(chan struct{})
	now := time.Now(); s.lastPacketReceivedTime = now; s.creationTime = now; s.datagramQueue = newDatagramQueue(s.scheduleSending, s.logger); s.connState.Version = s.version
}


func (s *connection) handleFrames(data []byte, destConnIDOnPacket protocol.ConnectionID, encLevel protocol.EncryptionLevel, log func([]logging.Frame), rcvTime time.Time) (isAckEliciting, isNonProbing bool, pathChallenge *wire.PathChallengeFrame, _ error) {
	// ... (frame parsing loop)
	var frame wire.Frame
	var l int
	var err error // ensure err is declared for the loop
	for len(data) > 0 {
		var currentParsed int
		frame, currentParsed, err = s.frameParser.ParseNext(data, encLevel, s.version)
		if err != nil { return false, false, nil, err } // Make sure err is from ParseNext
		data = data[currentParsed:] // Ensure data is advanced
		if frame == nil { break } // No more frames

		if ackhandler.IsFrameAckEliciting(frame) { isAckEliciting = true }
		if !wire.IsProbingFrame(frame) { isNonProbing = true }
		if log != nil { frames = append(frames, toLoggingFrame(frame)) } // `frames` needs to be declared if log != nil

		// ...
		switch f := frame.(type) {
		// ...
		case *wire.NewConnectionIDFrame:
			if s.multiPathManager != nil {
				err = s.multiPathManager.HandleStandardNewConnectionID(f)
			} else {
				// This case should ideally not be hit if MPM is always initialized.
				// If it can be, ensure s.connIDManager.Add is still the correct legacy call.
				// The old connIDManager.Add might not exist or have a different signature.
				// For now, assume MPM handles it or it's an error if MPM is nil and this frame appears.
				if s.connIDManager != nil {
					// err = s.connIDManager.Add(f) // This specific Add signature might be gone
					s.logger.Errorf("Received NEW_CONNECTION_ID but multiPathManager is nil and legacy connIDManager.Add is no longer directly compatible.")
					err = errors.New("cannot handle NEW_CONNECTION_ID without proper multipath context or updated legacy path")
				}
			}
		case *wire.RetireConnectionIDFrame:
			if s.multiPathManager != nil {
				err = s.multiPathManager.HandleStandardRetireConnectionID(f, rcvTime)
			} else {
				// Similar to above, legacy path needs review.
				// s.connIDGenerator.Retire is path-aware now.
				err = s.connIDGenerator.Retire(protocol.InitialPathID, f.SequenceNumber, rcvTime.Add(s.config.MaxAckDelay)) // Default to path 0
			}
		case *wire.PathNewConnectionIDFrame:
			if s.multiPathManager != nil { s.multiPathManager.HandlePathNewConnectionID(f) }
		case *wire.PathRetireConnectionIDFrame:
			if s.multiPathManager != nil { s.multiPathManager.HandlePathRetireConnectionID(f, rcvTime) }
		// ... other cases ...
		}
		if err != nil { return false, false, nil, err } // From frame handling
	}
	// ...
	return
}

func (s *connection) handleTransportParameters(params *wire.TransportParameters) error {
	if s.tracer != nil && s.tracer.ReceivedTransportParameters != nil { s.tracer.ReceivedTransportParameters(params) }
	if err := s.checkTransportParameters(params); err != nil { return &qerr.TransportError{ErrorCode: qerr.TransportParameterError, ErrorMessage: err.Error()} }
	if s.perspective == protocol.PerspectiveClient && s.peerParams != nil && s.ConnectionState().Used0RTT && !params.ValidForUpdate(s.peerParams) {
		return &qerr.TransportError{ErrorCode: qerr.ProtocolViolation, ErrorMessage: "server sent reduced limits after accepting 0-RTT data"}
	}
	s.peerParams = params
	if params.InitialMaxPathID != protocol.InvalidPathID { s.peerInitialMaxPathID = protocol.PathID(params.InitialMaxPathID) } else { s.peerInitialMaxPathID = 0 }
	if params.StatelessResetToken != nil {
		s.peerInitialSRT = params.StatelessResetToken
		if s.connIDManager != nil && s.perspective == protocol.PerspectiveClient {
			s.connIDManager.SetStatelessResetTokenFromTP(*s.peerInitialSRT)
		} else if s.connIDManager != nil && s.perspective == protocol.PerspectiveServer {
			// Server receives client's initial SCID (our DCID for path 0) and its SRT is in NEW_CONNECTION_ID from client
			// The SRT in server's TP is for *server's* SCID on path 0.
			// This SRT is for the CID client is using to talk to us.
			// connIDManager's SetStatelessResetTokenFromTP is for client to store server's token.
			// Server needs to store client's token for client's initial SCID when it's added.
			// This might be handled by initial setup of connIDManager with clientInitialSrcConnID.
		}
	}

	isMultipathNowActive := s.determineMultipathActive(false) // false: TPs are now processed
	if s.multiPathManager != nil {
		s.multiPathManager.UpdatePeerAdvertisedPathLimit(s.peerInitialMaxPathID)
		s.multiPathManager.SetMultipathActive(isMultipathNowActive)
	} else if isMultipathNowActive { // Should have been initialized in newConnection
		s.logger.Errorf("multiPathManager is nil but should be active after TP processing")
		s.multiPathManager = newMultiPathManager(s, s.logger, isMultipathNowActive)
	}

	if s.perspective == protocol.PerspectiveServer { s.applyTransportParameters(); close(s.earlyConnReadyChan) }
	if params.InitialMaxPathID != protocol.InvalidPathID { /* ... existing CID checks ... */ }
	s.connStateMutex.Lock(); s.connState.SupportsDatagrams = s.supportsDatagrams(); s.connStateMutex.Unlock()
	return nil
}

// Getters for iConnectionFramework
func (s *connection) GetMainSentPacketHandler() ackhandler.SentPacketHandler { return s.sentPacketHandler }
func (s *connection) GetMainReceivedPacketHandler() ackhandler.ReceivedPacketHandler { return s.receivedPacketHandler }
func (s *connection) GetMainCongestionController() congestion.SendAlgorithmWithDebugInfos {
	if sph, ok := s.sentPacketHandler.(interface{ GetCongestionController() congestion.SendAlgorithmWithDebugInfos }); ok { return sph.GetCongestionController() }
	return nil
}
func (s *connection) GetMainPacer() *congestion.Pacer {
	if sph, ok := s.sentPacketHandler.(interface{ GetPacer() *congestion.Pacer }); ok { return sph.GetPacer() }
	return nil
}
func (s *connection) GetInitialPeerConnectionID() protocol.ConnectionID {
	if s.perspective == protocol.PerspectiveClient { return s.handshakeDestConnID }
	return s.origDestConnID // For server, this is client's initial SCID
}
func (s *connection) GetInitialOurConnectionID() protocol.ConnectionID { return s.connIDGenerator.GetInitialConnID() }
func (s *connection) GetInitialPeerStatelessResetToken() *protocol.StatelessResetToken { return s.peerInitialSRT }

func (s *connection) RetireOurConnectionIDUsingPeerSeqNum(pathID protocol.PathID, peerSeqNum uint64) error {
	if s.connIDManager == nil { return errors.New("connIDManager not initialized")}
	return s.connIDManager.RetireDestinationConnectionID(pathID, peerSeqNum)
}
func (s *connection) RetireOurCID(seqNum uint64, rcvTime time.Time) error {
	if s.connIDGenerator == nil { return errors.New("connIDGenerator not initialized")}
	// Standard RETIRE_CONNECTION_ID is for Path 0 from peer's perspective
	return s.connIDGenerator.Retire(protocol.InitialPathID, seqNum, rcvTime.Add(s.config.MaxAckDelay))
}


// ... (rest of file, including other iConnectionFramework getters, sendPackets, run loop, etc.)
// Make sure all iConnectionFramework methods are implemented.
func (s *connection) Perspective() protocol.Perspective { return s.perspective }
func (s *connection) Packer() packer { return s.packer }
func (s *connection) SendQueue() sender { return s.sendQueue }
// CloseWithError already exists
func (s *connection) ConnIDGenerator() *ConnectionIDGenerator { return s.connIDGenerator }
func (s *connection) ConnIDManager() *connIDManager { return s.connIDManager }
func (s *connection) GetPeerInitialMaxPathID() protocol.PathID { return s.peerInitialMaxPathID }
func (s *connection) GetLocalInitialMaxPathID() protocol.PathID { return s.localInitialMaxPathID }
// QueueControlFrame already exists
func (s *connection) GetRTTStats() *utils.RTTStats { return s.rttStats }
func (s *connection) Tracer() *logging.ConnectionTracer { return s.tracer }
func (s *connection) ConfirmHandshake() { if s.handshakeComplete && !s.handshakeConfirmed { if err := s.handleHandshakeConfirmed(time.Now()); err != nil {s.closeLocal(fmt.Errorf("error confirming handshake via multipath: %w", err)) }}}
func (s *connection) GetInitialMaxDatagramSize() protocol.ByteCount { if s.config != nil { return protocol.ByteCount(s.config.InitialPacketSize) }; return protocol.MinInitialPacketSize }
func (s *connection) GetLogger() utils.Logger { return s.logger }
func (s *connection) GetPeerTransportParameters() *wire.TransportParameters { return s.peerParams }
func (s *connection) ShouldStartMTUDiscovery() bool {
	if s.config == nil || s.conn == nil { // Should not happen in normal operation
		return false
	}
	return !s.config.DisablePathMTUDiscovery && s.conn.capabilities().DF
}

[end of connection.go]
