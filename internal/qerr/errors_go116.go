// +build go1.16

package qerr

import (
	"net"
)

func (e *TransportError) Is(target error) bool          { return target == net.ErrClosed }
func (e *ApplicationError) Is(target error) bool        { return target == net.ErrClosed }
func (e *IdleTimeoutError) Is(target error) bool        { return target == net.ErrClosed }
func (e *HandshakeTimeoutError) Is(target error) bool   { return target == net.ErrClosed }
func (e *VersionNegotiationError) Is(target error) bool { return target == net.ErrClosed }
func (e *StatelessResetError) Is(target error) bool     { return target == net.ErrClosed }
