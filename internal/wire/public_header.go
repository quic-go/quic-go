package wire

import (
	"bytes"
	"errors"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	// ErrPacketWithUnknownVersion occurs when a packet with an unknown version is parsed.
	// This can happen when the server is restarted. The client will send a packet without a version number.
	ErrPacketWithUnknownVersion          = errors.New("PublicHeader: Received a packet without version number, that we don't know the version for")
	errResetAndVersionFlagSet            = errors.New("PublicHeader: Reset Flag and Version Flag should not be set at the same time")
	errReceivedTruncatedConnectionID     = qerr.Error(qerr.InvalidPacketHeader, "receiving packets with truncated ConnectionID is not supported")
	errInvalidConnectionID               = qerr.Error(qerr.InvalidPacketHeader, "connection ID cannot be 0")
	errGetLengthNotForVersionNegotiation = errors.New("PublicHeader: GetLength cannot be called for VersionNegotiation packets")
)

// The PublicHeader of a QUIC packet. Warning: This struct should not be considered stable and will change soon.
type PublicHeader struct {
	Raw                  []byte
	ConnectionID         protocol.ConnectionID
	VersionFlag          bool
	ResetFlag            bool
	TruncateConnectionID bool
	PacketNumberLen      protocol.PacketNumberLen
	PacketNumber         protocol.PacketNumber
	VersionNumber        protocol.VersionNumber   // VersionNumber sent by the client
	SupportedVersions    []protocol.VersionNumber // VersionNumbers sent by the server
	DiversificationNonce []byte
}

// Write writes a public header. Warning: This API should not be considered stable and will change soon.
func (h *PublicHeader) Write(b *bytes.Buffer, version protocol.VersionNumber, pers protocol.Perspective) error {
	publicFlagByte := uint8(0x00)

	if h.VersionFlag && h.ResetFlag {
		return errResetAndVersionFlagSet
	}

	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}
	if !h.TruncateConnectionID {
		publicFlagByte |= 0x08
	}

	if len(h.DiversificationNonce) > 0 {
		if len(h.DiversificationNonce) != 32 {
			return errors.New("invalid diversification nonce length")
		}
		publicFlagByte |= 0x04
	}

	// only set PacketNumberLen bits if a packet number will be written
	if h.hasPacketNumber(pers) {
		switch h.PacketNumberLen {
		case protocol.PacketNumberLen1:
			publicFlagByte |= 0x00
		case protocol.PacketNumberLen2:
			publicFlagByte |= 0x10
		case protocol.PacketNumberLen4:
			publicFlagByte |= 0x20
		case protocol.PacketNumberLen6:
			publicFlagByte |= 0x30
		}
	}

	b.WriteByte(publicFlagByte)

	if !h.TruncateConnectionID {
		// always read the connection ID in little endian
		utils.LittleEndian.WriteUint64(b, uint64(h.ConnectionID))
	}

	if h.VersionFlag && pers == protocol.PerspectiveClient {
		utils.LittleEndian.WriteUint32(b, protocol.VersionNumberToTag(h.VersionNumber))
	}

	if len(h.DiversificationNonce) > 0 {
		b.Write(h.DiversificationNonce)
	}

	// if we're a server, and the VersionFlag is set, we must not include anything else in the packet
	if !h.hasPacketNumber(pers) {
		return nil
	}

	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(h.PacketNumber))
	case protocol.PacketNumberLen2:
		utils.GetByteOrder(version).WriteUint16(b, uint16(h.PacketNumber))
	case protocol.PacketNumberLen4:
		utils.GetByteOrder(version).WriteUint32(b, uint32(h.PacketNumber))
	case protocol.PacketNumberLen6:
		utils.GetByteOrder(version).WriteUint48(b, uint64(h.PacketNumber)&(1<<48-1))
	default:
		return errors.New("PublicHeader: PacketNumberLen not set")
	}

	return nil
}

// PeekConnectionID parses the connection ID from a QUIC packet's public header.
// If no error occurs, it restores the read position in the bytes.Reader.
func PeekConnectionID(b *bytes.Reader, packetSentBy protocol.Perspective) (protocol.ConnectionID, error) {
	var connectionID protocol.ConnectionID
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	// unread the public flag byte
	defer b.UnreadByte()

	truncateConnectionID := publicFlagByte&0x08 == 0
	if truncateConnectionID && packetSentBy == protocol.PerspectiveClient {
		return 0, errReceivedTruncatedConnectionID
	}
	if !truncateConnectionID {
		connID, err := utils.LittleEndian.ReadUint64(b)
		if err != nil {
			return 0, err
		}
		connectionID = protocol.ConnectionID(connID)
		// unread the connection ID
		for i := 0; i < 8; i++ {
			b.UnreadByte()
		}
	}
	return connectionID, nil
}

// ParsePublicHeader parses a QUIC packet's public header.
// The packetSentBy is the perspective of the peer that sent this PublicHeader, i.e. if we're the server, packetSentBy should be PerspectiveClient.
// Warning: This API should not be considered stable and will change soon.
func ParsePublicHeader(b *bytes.Reader, packetSentBy protocol.Perspective, version protocol.VersionNumber) (*PublicHeader, error) {
	header := &PublicHeader{}

	// First byte
	publicFlagByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	header.ResetFlag = publicFlagByte&0x02 > 0
	header.VersionFlag = publicFlagByte&0x01 > 0
	if version == protocol.VersionUnknown && !(header.VersionFlag || header.ResetFlag) {
		return nil, ErrPacketWithUnknownVersion
	}

	// TODO: activate this check once Chrome sends the correct value
	// see https://github.com/lucas-clemente/quic-go/issues/232
	// if publicFlagByte&0x04 > 0 {
	// 	return nil, errors.New("diversification nonces should only be sent by servers")
	// }

	header.TruncateConnectionID = publicFlagByte&0x08 == 0
	if header.TruncateConnectionID && packetSentBy == protocol.PerspectiveClient {
		return nil, errReceivedTruncatedConnectionID
	}

	if header.hasPacketNumber(packetSentBy) {
		switch publicFlagByte & 0x30 {
		case 0x30:
			header.PacketNumberLen = protocol.PacketNumberLen6
		case 0x20:
			header.PacketNumberLen = protocol.PacketNumberLen4
		case 0x10:
			header.PacketNumberLen = protocol.PacketNumberLen2
		case 0x00:
			header.PacketNumberLen = protocol.PacketNumberLen1
		}
	}

	// Connection ID
	if !header.TruncateConnectionID {
		var connID uint64
		// always write the connection ID in little endian
		connID, err = utils.LittleEndian.ReadUint64(b)
		if err != nil {
			return nil, err
		}
		header.ConnectionID = protocol.ConnectionID(connID)
		if header.ConnectionID == 0 {
			return nil, errInvalidConnectionID
		}
	}

	if packetSentBy == protocol.PerspectiveServer && publicFlagByte&0x04 > 0 {
		// TODO: remove the if once the Google servers send the correct value
		// assume that a packet doesn't contain a diversification nonce if the version flag or the reset flag is set, no matter what the public flag says
		// see https://github.com/lucas-clemente/quic-go/issues/232
		if !header.VersionFlag && !header.ResetFlag {
			header.DiversificationNonce = make([]byte, 32)
			if _, err := io.ReadFull(b, header.DiversificationNonce); err != nil {
				return nil, err
			}
		}
	}

	// Version (optional)
	if !header.ResetFlag && header.VersionFlag {
		if packetSentBy == protocol.PerspectiveServer { // parse the version negotiaton packet
			if b.Len()%4 != 0 {
				return nil, qerr.InvalidVersionNegotiationPacket
			}
			header.SupportedVersions = make([]protocol.VersionNumber, 0)
			for {
				var versionTag uint32
				versionTag, err = utils.LittleEndian.ReadUint32(b)
				if err != nil {
					break
				}
				v := protocol.VersionTagToNumber(versionTag)
				header.SupportedVersions = append(header.SupportedVersions, v)
			}
			// a version negotiation packet doesn't have a packet number
			return header, nil
		}
		// packet was sent by the client. Read the version number
		var versionTag uint32
		versionTag, err = utils.LittleEndian.ReadUint32(b)
		if err != nil {
			return nil, err
		}
		header.VersionNumber = protocol.VersionTagToNumber(versionTag)
		version = header.VersionNumber
	}

	// Packet number
	if header.hasPacketNumber(packetSentBy) {
		packetNumber, err := utils.GetByteOrder(version).ReadUintN(b, uint8(header.PacketNumberLen))
		if err != nil {
			return nil, err
		}
		header.PacketNumber = protocol.PacketNumber(packetNumber)
	}

	return header, nil
}

// GetLength gets the length of the publicHeader in bytes.
// It can only be called for regular packets.
func (h *PublicHeader) GetLength(pers protocol.Perspective) (protocol.ByteCount, error) {
	if h.VersionFlag && h.ResetFlag {
		return 0, errResetAndVersionFlagSet
	}

	if h.VersionFlag && pers == protocol.PerspectiveServer {
		return 0, errGetLengthNotForVersionNegotiation
	}

	length := protocol.ByteCount(1) // 1 byte for public flags

	if h.hasPacketNumber(pers) {
		if h.PacketNumberLen != protocol.PacketNumberLen1 && h.PacketNumberLen != protocol.PacketNumberLen2 && h.PacketNumberLen != protocol.PacketNumberLen4 && h.PacketNumberLen != protocol.PacketNumberLen6 {
			return 0, errPacketNumberLenNotSet
		}
		length += protocol.ByteCount(h.PacketNumberLen)
	}

	if !h.TruncateConnectionID {
		length += 8 // 8 bytes for the connection ID
	}

	// Version Number in packets sent by the client
	if h.VersionFlag {
		length += 4
	}

	length += protocol.ByteCount(len(h.DiversificationNonce))

	return length, nil
}

// hasPacketNumber determines if this PublicHeader will contain a packet number
// this depends on the ResetFlag, the VersionFlag and who sent the packet
func (h *PublicHeader) hasPacketNumber(packetSentBy protocol.Perspective) bool {
	if h.ResetFlag {
		return false
	}
	if h.VersionFlag && packetSentBy == protocol.PerspectiveServer {
		return false
	}
	return true
}
