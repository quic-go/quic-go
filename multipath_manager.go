// multipath_manager.go
package quic

import (
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// PathState defines the state of a network path.
type PathState uint8

const (
	// PathStateValidating indicates the path is undergoing validation (e.g., PATH_CHALLENGE sent).
	PathStateValidating PathState = iota
	// PathStateActive indicates the path is validated and available for sending data.
	PathStateActive
	// PathStateClosing indicates the path is being closed (e.g., NEW_CONNECTION_ID with retire_prior_to used).
	PathStateClosing
	// PathStateClosed indicates the path is no longer in use.
	PathStateClosed
)

func (s PathState) String() string {
	switch s {
	case PathStateValidating:
		return "VALIDATING"
	case PathStateActive:
		return "ACTIVE"
	case PathStateClosing:
		return "CLOSING"
	case PathStateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// pathPacketNumberSpace holds packet number related state for a single path.
type pathPacketNumberSpace struct {
	pnGen ackhandler.PacketNumberGenerator
}

// multipathManager manages multiple paths for a QUIC connection.
type multipathManager struct {
	mutex sync.RWMutex
	paths []*path // Slice of active and validating paths

	rttStats    *utils.RTTStats
	config      *Config
	tracer      *logging.ConnectionTracer
	perspective protocol.Perspective
}

// newMultipathManager creates a new multipathManager.
func newMultipathManager(
	rttStats *utils.RTTStats,
	config *Config,
	tracer *logging.ConnectionTracer,
	perspective protocol.Perspective,
) *multipathManager {
	return &multipathManager{
		paths:       make([]*path, 0, 1), // Initial capacity for the primary path
		rttStats:    rttStats,
		config:      config,
		tracer:      tracer,
		perspective: perspective,
	}
}

func (m *multipathManager) addPath(remoteAddr net.Addr, pathID uint64, negotiatedMaxConnPaths uint64, peerMaxUDPPayloadSize protocol.ByteCount) (*path, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, p := range m.paths {
		if p.pathID == pathID {
			if !utils.AreAddressesEqual(p.RemoteAddr, remoteAddr) && remoteAddr != nil {
				if m.tracer != nil && m.tracer.PathRemoteAddressChanged != nil {
					m.tracer.PathRemoteAddressChanged(pathID, p.RemoteAddr, remoteAddr)
				}
				p.RemoteAddr = remoteAddr
			}
			return p, nil
		}
	}

	if uint64(len(m.paths)) >= negotiatedMaxConnPaths && negotiatedMaxConnPaths > 0 { // negotiatedMaxConnPaths > 0 means the limit is active
		return nil, errors.New("cannot add new path: maximum number of paths reached according to negotiation")
	}

	newPath := &path{
		pathID:     pathID,
		RemoteAddr: remoteAddr,
		State:      PathStateValidating, // Initial state
		// Initialize packet number space for the new path.
		// Each path starts with packet number 0 conceptually for its own space.
		pnSpace:    &pathPacketNumberSpace{pnGen: ackhandler.NewPacketNumberGenerator(protocol.InitialPacketNumber)},
	}

	initialMTU := protocol.ByteCount(m.config.InitialPacketSize)
	maxMTU := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if peerMaxUDPPayloadSize > 0 && peerMaxUDPPayloadSize < maxMTU {
		maxMTU = peerMaxUDPPayloadSize
	}

	newPath.mtuDiscoverer = newMTUDiscoverer(
		m.rttStats,
		initialMTU,
		maxMTU,
		m.tracer,
	)

	m.paths = append(m.paths, newPath)
	if m.tracer != nil && m.tracer.PathAdded != nil {
		m.tracer.PathAdded(pathID, remoteAddr)
	}
	return newPath, nil
}

func (m *multipathManager) getPath(pathID uint64) *path {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	for _, p := range m.paths {
		if p.pathID == pathID {
			return p
		}
	}
	return nil
}

func (m *multipathManager) getPrimaryPath() *path {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	for _, p := range m.paths {
		if p.pathID == 0 {
			return p
		}
	}
	return nil
}

func (m *multipathManager) getActivePaths() []*path {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	activePaths := make([]*path, 0, len(m.paths))
	for _, p := range m.paths {
		if p.State == PathStateActive {
			activePaths = append(activePaths, p)
		}
	}
	return activePaths
}

func (m *multipathManager) setPathState(pathID uint64, newState PathState) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for _, p := range m.paths {
		if p.pathID == pathID {
			if p.State != newState {
				if m.tracer != nil && m.tracer.PathStateChanged != nil {
					m.tracer.PathStateChanged(pathID, p.RemoteAddr, p.State, newState)
				}
				p.State = newState
			}
			return true
		}
	}
	return false
}
