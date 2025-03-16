package quic

import (
	"crypto/rand"
	"net"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type pathID int64

const maxPaths = 3

type path struct {
	addr           net.Addr
	pathChallenge  [8]byte
	validated      bool
	rcvdNonProbing bool
}

type pathManager struct {
	nextPathID pathID
	paths      map[pathID]*path

	getConnID    func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID func(pathID)

	logger utils.Logger
}

func newPathManager(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	logger utils.Logger,
) *pathManager {
	return &pathManager{
		paths:        make(map[pathID]*path),
		getConnID:    getConnID,
		retireConnID: retireConnID,
		logger:       logger,
	}
}

// Returns a path challenge frame if one should be sent.
// May return nil.
func (pm *pathManager) HandlePacket(
	remoteAddr net.Addr,
	pathChallenge *wire.PathChallengeFrame, // may be nil if the packet didn't contain a PATH_CHALLENGE
	isNonProbing bool,
) (_ protocol.ConnectionID, _ []ackhandler.Frame, shouldSwitch bool) {
	var p *path
	pathID := pm.nextPathID
	for id, path := range pm.paths {
		if addrsEqual(path.addr, remoteAddr) {
			p = path
			pathID = id
			// already sent a PATH_CHALLENGE for this path
			if isNonProbing {
				path.rcvdNonProbing = true
			}
			if pm.logger.Debug() {
				pm.logger.Debugf("received packet for path %s that was already probed, validated: %t", remoteAddr, path.validated)
			}
			shouldSwitch = path.validated && path.rcvdNonProbing
			if pathChallenge == nil {
				return protocol.ConnectionID{}, nil, shouldSwitch
			}
		}
	}

	if len(pm.paths) >= maxPaths {
		if pm.logger.Debug() {
			pm.logger.Debugf("received packet for previously unseen path %s, but already have %d paths", remoteAddr, len(pm.paths))
		}
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	// previously unseen path, initiate path validation by sending a PATH_CHALLENGE
	connID, ok := pm.getConnID(pathID)
	if !ok {
		pm.logger.Debugf("skipping validation of new path %s since no connection ID is available", remoteAddr)
		return protocol.ConnectionID{}, nil, shouldSwitch
	}

	frames := make([]ackhandler.Frame, 0, 2)
	if p == nil {
		var pathChallengeData [8]byte
		rand.Read(pathChallengeData[:])
		p = &path{
			addr:           remoteAddr,
			rcvdNonProbing: isNonProbing,
			pathChallenge:  pathChallengeData,
		}
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathChallengeFrame{Data: p.pathChallenge},
			Handler: (*pathManagerAckHandler)(pm),
		})
		pm.paths[pm.nextPathID] = p
		pm.nextPathID++
		pm.logger.Debugf("enqueueing PATH_CHALLENGE for new path %s", remoteAddr)
	}
	if pathChallenge != nil {
		frames = append(frames, ackhandler.Frame{
			Frame:   &wire.PathResponseFrame{Data: pathChallenge.Data},
			Handler: (*pathManagerAckHandler)(pm),
		})
	}
	return connID, frames, shouldSwitch
}

func (pm *pathManager) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	for _, p := range pm.paths {
		if f.Data == p.pathChallenge {
			// path validated
			p.validated = true
			pm.logger.Debugf("path %s validated", p.addr)
			break
		}
	}
}

// SwitchToPath is called when the connection switches to a new path
func (pm *pathManager) SwitchToPath(addr net.Addr) {
	// retire all other paths
	for id := range pm.paths {
		if addrsEqual(pm.paths[id].addr, addr) {
			pm.logger.Debugf("switching to path %d (%s)", id, addr)
			continue
		}
		pm.retireConnID(id)
	}
	clear(pm.paths)
}

type pathManagerAckHandler pathManager

var _ ackhandler.FrameHandler = &pathManagerAckHandler{}

// Acknowledging the frame doesn't validate the path, only receiving the PATH_RESPONSE does.
func (pm *pathManagerAckHandler) OnAcked(f wire.Frame) {}

func (pm *pathManagerAckHandler) OnLost(f wire.Frame) {
	// TODO: retransmit the packet the first time it is lost
	pc := f.(*wire.PathChallengeFrame)
	for id, path := range pm.paths {
		if path.pathChallenge == pc.Data {
			delete(pm.paths, id)
			pm.retireConnID(id)
			break
		}
	}
}

func addrsEqual(addr1, addr2 net.Addr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	a1, ok1 := addr1.(*net.UDPAddr)
	a2, ok2 := addr2.(*net.UDPAddr)
	if ok1 && ok2 {
		return a1.IP.Equal(a2.IP) && a1.Port == a2.Port
	}
	return addr1.String() == addr2.String()
}
