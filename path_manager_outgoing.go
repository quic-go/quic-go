package quic

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

type pathOutgoing struct {
	pathChallenge [8]byte
	tr            *Transport
	validated     chan<- struct{} // closed when the path the corresponding PATH_RESPONSE is received
}

type pathManagerOutgoing struct {
	getConnID       func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID    func(pathID)
	scheduleSending func()

	mx           sync.Mutex
	pathsToProbe []*pathOutgoing
	lostPaths    []pathID
	paths        map[pathID]*pathOutgoing
	nextPathID   pathID
}

func newPathManagerOutgoing(
	getConnID func(pathID) (_ protocol.ConnectionID, ok bool),
	retireConnID func(pathID),
	scheduleSending func(),
) *pathManagerOutgoing {
	return &pathManagerOutgoing{
		getConnID:       getConnID,
		retireConnID:    retireConnID,
		scheduleSending: scheduleSending,
		paths:           make(map[pathID]*pathOutgoing),
	}
}

func (pm *pathManagerOutgoing) AddPath(t *Transport, done chan<- struct{}) {
	pm.mx.Lock()
	pm.pathsToProbe = append(pm.pathsToProbe, &pathOutgoing{tr: t, validated: done})
	pm.mx.Unlock()
	pm.scheduleSending()
}

func (pm *pathManagerOutgoing) NextPathToProbe() (_ protocol.ConnectionID, _ ackhandler.Frame, _ *Transport, ok bool) {
	fmt.Println("NextPathToProbe")
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if len(pm.pathsToProbe) == 0 && len(pm.lostPaths) == 0 {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}

	// TODO: handle lost paths

	p := pm.pathsToProbe[0]
	pm.pathsToProbe = pm.pathsToProbe[1:]

	connID, ok := pm.getConnID(pm.nextPathID)
	if !ok {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}
	var b [8]byte
	rand.Read(b[:])
	p.pathChallenge = b
	pm.paths[pm.nextPathID] = p
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: b},
		Handler: (*pathManagerOutgoingAckHandler)(pm),
	}
	pm.nextPathID++
	fmt.Println("probing path", connID)
	return connID, frame, p.tr, true
}

func (pm *pathManagerOutgoing) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	fmt.Println("HandlePathResponseFrame", f)
	pm.mx.Lock()
	defer pm.mx.Unlock()

	for _, p := range pm.paths {
		if f.Data == p.pathChallenge {
			// path validated
			fmt.Println("path validated", f.Data)
			if p.validated != nil {
				close(p.validated)
			}
			// makes sure that duplicate PATH_RESPONSE frames are ignored
			p.validated = nil
			break
		}
	}
}

type pathManagerOutgoingAckHandler pathManagerOutgoing

var _ ackhandler.FrameHandler = &pathManagerOutgoingAckHandler{}

// Acknowledging the frame doesn't validate the path, only receiving the PATH_RESPONSE does.
func (pm *pathManagerOutgoingAckHandler) OnAcked(f wire.Frame) {}

func (pm *pathManagerOutgoingAckHandler) OnLost(f wire.Frame) {
	pc := f.(*wire.PathChallengeFrame)
	for id, path := range pm.paths {
		if path.pathChallenge == pc.Data {
			pm.lostPaths = append(pm.lostPaths, id)
			break
		}
	}
}
