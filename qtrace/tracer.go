package qtrace

import (
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// The Tracer can be attached to a connection within the usual quic
// configuration of a client/server. The corresponding functions
// are called if provided. In example/trace/trace.go an exemplary use
// of the Tracer can be found.
type Tracer struct {
	GotPacket func(protocol.EncryptionLevel, []frames.Frame)
	SentPacket func(protocol.PacketNumber, []byte, []frames.Frame, protocol.EncryptionLevel)

	GotFrame func(frame frames.Frame)
	SentFrame func(frame frames.Frame)

	ClientSentCHLO func(interface{})         // handshake.HandshakeMessage
	ClientGotHandshakeMsg func(interface{})  // handshake.HandshakeMessage

	ServerSentCHLO func(interface{})         // handshake.HandshakeMessage
	ServerSentInchoateCHLO func(interface{}) // handshake.HandshakeMessage
	ServerGotHandshakeMsg func(interface{})  // handshake.HandshakeMessage

	// The Tracer uses interface{} to avoid import cycles. Therefore
	// the receiving functions may cast the parameter back to the
	// original datatypes. E.g.:
	// func ClientSentCHLO(x interface{}){
	//     message, ok := x.(handshake.HandshakeMessage)
	//     if ok {
	//         fmt.Println("ClientSentCHLO")
	//         fmt.Println("  Message:\t\t", message)
	//     }
	// }
}


