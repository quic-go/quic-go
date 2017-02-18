package publicheader

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

// ComposeVersionNegotiation returns a Version Negotiation Packet
func ComposeVersionNegotiation(connectionID protocol.ConnectionID) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{
		ConnectionID: connectionID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	err := responsePublicHeader.Write(fullReply, protocol.Version35, protocol.PerspectiveServer)
	if err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
	}
	fullReply.Write(protocol.SupportedVersionsAsTags)
	return fullReply.Bytes()
}
