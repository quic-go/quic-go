package quic

type ServerTrace struct {
	HandshakeStart func()
	HandshakeDone  func()
	ReceivePacket  func()
	HandlePacket   func()
	ConnectRefused func()
	TokenInvalid   func()
}
