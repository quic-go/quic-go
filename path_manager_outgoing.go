package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
)

// ErrPathNotValidated is returned when trying to use a path before path probing has completed.
var ErrPathNotValidated = errors.New("path not yet validated")

var errPathDoesNotExist = errors.New("path does not exist")

// Path is a network path.
type Path struct {
	id          pathID
	pathManager *pathManagerOutgoing
	tr          *Transport

	enablePath     func()
	startedProbing atomic.Bool
}

func (p *Path) Probe(ctx context.Context) error {
	done := make(chan struct{})
	p.pathManager.addPath(p, p.enablePath, done)

	p.startedProbing.Store(true)
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-done:
		return nil
	}
}

// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
func (p *Path) Switch() error {
	if err := p.pathManager.switchToPath(p.id); err != nil {
		if errors.Is(err, errPathDoesNotExist) && !p.startedProbing.Load() {
			return ErrPathNotValidated
		}
		return err
	}
	return nil
}

type pathOutgoing struct {
	pathChallenge [8]byte
	tr            *Transport
	isValidated   bool
	validated     chan<- struct{} // closed when the path the corresponding PATH_RESPONSE is received
	enablePath    func()
}

type pathManagerOutgoing struct {
	getConnID       func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID    func(pathID)
	scheduleSending func()

	mx             sync.Mutex
	pathsToProbe   []pathID
	paths          map[pathID]*pathOutgoing
	nextPathID     pathID
	pathToSwitchTo *pathOutgoing
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
		paths:           make(map[pathID]*pathOutgoing, 4),
	}
}

func (pm *pathManagerOutgoing) addPath(p *Path, enablePath func(), done chan<- struct{}) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	pm.mx.Lock()
	pm.paths[p.id] = &pathOutgoing{
		pathChallenge: b,
		tr:            p.tr,
		validated:     done,
		enablePath:    enablePath,
	}
	pm.pathsToProbe = append(pm.pathsToProbe, p.id)
	pm.mx.Unlock()
	pm.scheduleSending()
}

func (pm *pathManagerOutgoing) switchToPath(id pathID) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	p, ok := pm.paths[id]
	if !ok {
		return errPathDoesNotExist
	}
	if !p.isValidated {
		return ErrPathNotValidated
	}
	pm.pathToSwitchTo = p
	return nil
}

func (pm *pathManagerOutgoing) NewPath(t *Transport, enablePath func()) *Path {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	id := pm.nextPathID
	pm.nextPathID++
	return &Path{
		pathManager: pm,
		id:          id,
		tr:          t,
		enablePath:  enablePath,
	}
}

func (pm *pathManagerOutgoing) NextPathToProbe() (_ protocol.ConnectionID, _ ackhandler.Frame, _ *Transport, hasPath bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	var p *pathOutgoing
	var id pathID
	for {
		if len(pm.pathsToProbe) == 0 {
			return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
		}

		id = pm.pathsToProbe[0]
		pm.pathsToProbe = pm.pathsToProbe[1:]

		var ok bool
		// if the path doesn't exist in the map, it might have been abandoned
		p, ok = pm.paths[id]
		if ok {
			break
		}
	}

	connID, ok := pm.getConnID(id)
	if !ok {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}

	p.enablePath()
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: p.pathChallenge},
		Handler: (*pathManagerOutgoingAckHandler)(pm),
	}
	return connID, frame, p.tr, true
}

func (pm *pathManagerOutgoing) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	for _, p := range pm.paths {
		if f.Data == p.pathChallenge {
			// path validated
			if !p.isValidated {
				p.isValidated = true
				close(p.validated)
			}
			// makes sure that duplicate PATH_RESPONSE frames are ignored
			p.validated = nil
			break
		}
	}
}

func (pm *pathManagerOutgoing) ShouldSwitchPath() (*Transport, bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if pm.pathToSwitchTo == nil {
		return nil, false
	}
	p := pm.pathToSwitchTo
	pm.pathToSwitchTo = nil
	return p.tr, true
}

type pathManagerOutgoingAckHandler pathManagerOutgoing

var _ ackhandler.FrameHandler = &pathManagerOutgoingAckHandler{}

// OnAcked is called when the PATH_CHALLENGE is acked.
// This doesn't validate the path, only receiving the PATH_RESPONSE does.
func (pm *pathManagerOutgoingAckHandler) OnAcked(wire.Frame) {}

func (pm *pathManagerOutgoingAckHandler) OnLost(wire.Frame) {}
