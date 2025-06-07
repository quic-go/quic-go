package quic

import "context"

func (c *wrappedConn) run() error {
	if c.testHooks == nil {
		return c.Conn.run()
	}
	if c.testHooks.run != nil {
		return c.testHooks.run()
	}
	return nil
}

func (c *wrappedConn) earlyConnReady() <-chan struct{} {
	if c.testHooks == nil {
		return c.Conn.earlyConnReady()
	}
	if c.testHooks.earlyConnReady != nil {
		return c.testHooks.earlyConnReady()
	}
	return nil
}

func (c *wrappedConn) Context() context.Context {
	if c.testHooks == nil {
		return c.Conn.Context()
	}
	if c.testHooks.context != nil {
		return c.testHooks.context()
	}
	return context.Background()
}

func (c *wrappedConn) HandshakeComplete() <-chan struct{} {
	if c.testHooks == nil {
		return c.Conn.HandshakeComplete()
	}
	if c.testHooks.handshakeComplete != nil {
		return c.testHooks.handshakeComplete()
	}
	return nil
}

func (c *wrappedConn) closeWithTransportError(code TransportErrorCode) {
	if c.testHooks == nil {
		c.Conn.closeWithTransportError(code)
		return
	}
	if c.testHooks.closeWithTransportError != nil {
		c.testHooks.closeWithTransportError(code)
	}
}

func (c *wrappedConn) destroy(e error) {
	if c.testHooks == nil {
		c.Conn.destroy(e)
		return
	}
	if c.testHooks.destroy != nil {
		c.testHooks.destroy(e)
	}
}

func (c *wrappedConn) handlePacket(p receivedPacket) {
	if c.testHooks == nil {
		c.Conn.handlePacket(p)
		return
	}
	if c.testHooks.handlePacket != nil {
		c.testHooks.handlePacket(p)
	}
}
