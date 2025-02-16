package quic

import (
	"context"
)

// PathStatus is the status of a path.
type PathStatus uint8

const (
	// PathStatusProbing means that the path is being probed (i.e. a PATH_CHALLENGE frame has been sent).
	PathStatusProbing PathStatus = 1 + iota
	// PathStatusTimeout means that path probing ran into a timeout,
	// or that a previously successfully probed path was abandoned.
	PathStatusTimeout
	// PathStatusProbeSuccess means that path probing succeeded. It is now possible to switch to this path.
	PathStatusProbeSuccess
	// PathStatusActive means that this is the path that's used to send QUIC packets
	PathStatusActive
)

func (s PathStatus) String() string {
	switch s {
	case PathStatusProbing:
		return "probing"
	case PathStatusTimeout:
		return "timeout"
	case PathStatusProbeSuccess:
		return "probe success"
	case PathStatusActive:
		return "active"
	default:
		return "unknown path status"
	}
}

// Path is a network path.
type Path struct {
	pathManager *pathManagerOutgoing
	tr          *Transport

	// Notify is a channel (cap 1) that a new value is added to every time the status changes.
	// Note that the status can change even after path validation succeeded (e.g. because a path times out).
	Notify <-chan struct{}
}

func (p *Path) Probe(ctx context.Context) error {
	done := make(chan struct{})
	p.pathManager.AddPath(p.tr, done)

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-done:
		return nil
	}
}

// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
// It's only valid to call this function if the status is ProbeStatusProbeSuccess.
func (p *Path) Switch() error {
	return nil
}

// Abandon abandons a path.
// It is not possible to abandon the path that’s currently active.
// This stops the sending of keep-alive packets, eventually leading to a timeout of the path.
func (p *Path) Abandon() error {
	return nil
}
