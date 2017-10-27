package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ComposeVersionNegotiation composes a Version Negotiation Packet
// TODO(894): implement the IETF draft format of Version Negotiation Packets
func ComposeVersionNegotiation(connectionID protocol.ConnectionID, versions []protocol.VersionNumber) []byte {
	fullReply := &bytes.Buffer{}
	ph := Header{
		ConnectionID: connectionID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	err := ph.writePublicHeader(fullReply, protocol.PerspectiveServer, protocol.VersionWhatever)
	if err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
	}
	for _, v := range versions {
		utils.BigEndian.WriteUint32(fullReply, uint32(v))
	}
	return fullReply.Bytes()
}
