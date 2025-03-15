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

var (
	// ErrPathAbandoned is returned when trying to switch to a path that has been abandoned.
	ErrPathAbandoned = errors.New("path abandoned")
	// ErrPathNotValidated is returned when trying to use a path before path probing has completed.
	ErrPathNotValidated = errors.New("path not yet validated")
)

var errPathDoesNotExist = errors.New("path does not exist")

// Path is a network path.
type Path struct {
	id          pathID
	pathManager *pathManagerOutgoing
	tr          *Transport

	enablePath     func()
	startedProbing atomic.Bool
	abandon        chan struct{}
}

func (p *Path) Probe(ctx context.Context) error {
	done := make(chan struct{})
	p.pathManager.addPath(p, p.enablePath, done)

	p.startedProbing.Store(true)
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-p.abandon:
		return ErrPathAbandoned
	case <-done:
		return nil
	}
}

// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
func (p *Path) Switch() error {
	if err := p.pathManager.switchToPath(p.id); err != nil {
		switch {
		case errors.Is(err, ErrPathNotValidated):
			return err
		case errors.Is(err, errPathDoesNotExist) && !p.startedProbing.Load():
			return ErrPathNotValidated
		default:
			return ErrPathAbandoned
		}
	}
	return nil
}

// Close abandons a path.
// It is not possible to close the path that’s currently active.
// After closing, it is not possible to probe this path again by calling Probe.
func (p *Path) Close() error {
	select {
	case <-p.abandon:
		return ErrPathAbandoned
	default:
	}

	if err := p.pathManager.removePath(p.id); err != nil {
		return err
	}
	close(p.abandon)
	return nil
}

type pathOutgoing struct {
	tr *Transport

	pathChallenge *[8]byte
	isValidated   bool
	validated     chan<- struct{} // closed when the path the corresponding PATH_RESPONSE is received
	enablePath    func()
}

type pathManagerOutgoing struct {
	getConnID       func(pathID) (_ protocol.ConnectionID, ok bool)
	retireConnID    func(pathID)
	scheduleSending func()

	mx             sync.Mutex
	activePath     pathID
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
		activePath:      0, // at initialization time, we're guaranteed to be using the handshake path
		nextPathID:      1,
		getConnID:       getConnID,
		retireConnID:    retireConnID,
		scheduleSending: scheduleSending,
		paths:           make(map[pathID]*pathOutgoing, 4),
	}
}

func (pm *pathManagerOutgoing) addPath(p *Path, enablePath func(), done chan<- struct{}) {
	pm.mx.Lock()
	pm.paths[p.id] = &pathOutgoing{
		tr:         p.tr,
		validated:  done,
		enablePath: enablePath,
	}
	pm.pathsToProbe = append(pm.pathsToProbe, p.id)
	pm.mx.Unlock()
	pm.scheduleSending()
}

func (pm *pathManagerOutgoing) removePath(id pathID) error {
	if err := pm.removePathImpl(id); err != nil {
		return err
	}
	pm.scheduleSending()
	return nil
}

func (pm *pathManagerOutgoing) removePathImpl(id pathID) error {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	if id == pm.activePath {
		return errors.New("cannot remove active path")
	}
	p, ok := pm.paths[id]
	if !ok {
		return nil
	}
	if p.pathChallenge != nil {
		pm.retireConnID(id)
	}
	delete(pm.paths, id)
	return nil
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
		abandon:     make(chan struct{}),
	}
}

func (pm *pathManagerOutgoing) NextPathToProbe() (_ protocol.ConnectionID, _ ackhandler.Frame, _ *Transport, hasPath bool) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	var p *pathOutgoing
	id := invalidPathID
	for _, pID := range pm.pathsToProbe {
		var ok bool
		p, ok = pm.paths[pID]
		if ok {
			id = pID
			break
		}
		// if the path doesn't exist in the map, it might have been abandoned
		pm.pathsToProbe = pm.pathsToProbe[1:]
	}
	if id == invalidPathID {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}

	connID, ok := pm.getConnID(id)
	if !ok {
		return protocol.ConnectionID{}, ackhandler.Frame{}, nil, false
	}

	p.enablePath()
	var b [8]byte
	_, _ = rand.Read(b[:])
	p.pathChallenge = &b
	pm.pathsToProbe = pm.pathsToProbe[1:]
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: *p.pathChallenge},
		Handler: (*pathManagerOutgoingAckHandler)(pm),
	}
	return connID, frame, p.tr, true
}

func (pm *pathManagerOutgoing) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	for _, p := range pm.paths {
		if p.pathChallenge != nil && f.Data == *p.pathChallenge {
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
