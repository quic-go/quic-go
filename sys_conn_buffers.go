package quic

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

func setReceiveBuffer(c net.PacketConn, logger utils.Logger) error {
	conn, ok := c.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("connection doesn't allow setting of receive buffer size. Not a *net.UDPConn?")
	}
	size, err := inspectReadBuffer(c)
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if size >= protocol.DesiredReceiveBufferSize {
		logger.Debugf("Conn has receive buffer of %d kiB (wanted: at least %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024)
		return nil
	}
	// Ignore the error. We check if we succeeded by querying the buffer size afterward.
	_ = conn.SetReadBuffer(protocol.DesiredReceiveBufferSize)
	newSize, err := inspectReadBuffer(c)
	if newSize < protocol.DesiredReceiveBufferSize {
		// Try again with RCVBUFFORCE on Linux
		_ = forceSetReceiveBuffer(c, protocol.DesiredReceiveBufferSize)
		newSize, err = inspectReadBuffer(c)
		if err != nil {
			return fmt.Errorf("failed to determine receive buffer size: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if newSize == size {
		return fmt.Errorf("failed to increase receive buffer size (wanted: %d kiB, got %d kiB)", protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	if newSize < protocol.DesiredReceiveBufferSize {
		return fmt.Errorf("failed to sufficiently increase receive buffer size (was: %d kiB, wanted: %d kiB, got: %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	logger.Debugf("Increased receive buffer size to %d kiB", newSize/1024)
	return nil
}
