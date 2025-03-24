package quic

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

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
	initialRTT  time.Duration

	enablePath func()
	validated  atomic.Bool
}

func (p *Path) Probe(ctx context.Context) error {
	path := p.pathManager.addPath(p, p.enablePath)

	p.pathManager.enqueueProbe(p)
	nextProbeDur := p.initialRTT
	var timer *time.Timer
	var timerChan <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-path.Validated():
			p.validated.Store(true)
			return nil
		case <-timerChan:
			p.pathManager.enqueueProbe(p)
		case <-path.ProbeSent():
		}

		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(nextProbeDur)
		timerChan = timer.C
		nextProbeDur *= 2 // exponential backoff
	}
}

// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
func (p *Path) Switch() error {
	if err := p.pathManager.switchToPath(p.id); err != nil {
		if errors.Is(err, errPathDoesNotExist) && !p.validated.Load() {
			return ErrPathNotValidated
		}
		return err
	}
	return nil
}

type pathOutgoing struct {
	pathChallenges [][8]byte // length is implicitly limited by exponential backoff
	tr             *Transport
	isValidated    bool
	probeSent      chan struct{} // receives when a PATH_CHALLENGE is sent
	validated      chan struct{} // closed when the path the corresponding PATH_RESPONSE is received
	enablePath     func()
}

func (p *pathOutgoing) ProbeSent() <-chan struct{} { return p.probeSent }
func (p *pathOutgoing) Validated() <-chan struct{} { return p.validated }

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

func (pm *pathManagerOutgoing) addPath(p *Path, enablePath func()) *pathOutgoing {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	// path might already exist, and just being re-probed
	if existingPath, ok := pm.paths[p.id]; ok {
		existingPath.validated = make(chan struct{})
		return existingPath
	}

	path := &pathOutgoing{
		tr:         p.tr,
		probeSent:  make(chan struct{}, 1),
		validated:  make(chan struct{}),
		enablePath: enablePath,
	}
	pm.paths[p.id] = path
	return path
}

func (pm *pathManagerOutgoing) enqueueProbe(p *Path) {
	pm.mx.Lock()
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

func (pm *pathManagerOutgoing) NewPath(t *Transport, initialRTT time.Duration, enablePath func()) *Path {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	id := pm.nextPathID
	pm.nextPathID++
	return &Path{
		pathManager: pm,
		id:          id,
		tr:          t,
		enablePath:  enablePath,
		initialRTT:  initialRTT,
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

	var b [8]byte
	_, _ = rand.Read(b[:])
	p.pathChallenges = append(p.pathChallenges, b)

	p.enablePath()
	select {
	case p.probeSent <- struct{}{}:
	default:
	}
	frame := ackhandler.Frame{
		Frame:   &wire.PathChallengeFrame{Data: b},
		Handler: (*pathManagerOutgoingAckHandler)(pm),
	}
	return connID, frame, p.tr, true
}

func (pm *pathManagerOutgoing) HandlePathResponseFrame(f *wire.PathResponseFrame) {
	pm.mx.Lock()
	defer pm.mx.Unlock()

	for _, p := range pm.paths {
		if slices.Contains(p.pathChallenges, f.Data) {
			// path validated
			if !p.isValidated {
				// make sure that duplicate PATH_RESPONSE frames are ignored
				p.isValidated = true
				p.pathChallenges = nil
				close(p.validated)
			}
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
