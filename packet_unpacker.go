package quic

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type unpackedPacket struct {
	packetNumber    protocol.PacketNumber // the decoded packet number
	hdr             *wire.ExtendedHeader
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

// The packetUnpacker unpacks QUIC packets.
type packetUnpacker struct {
	cs handshake.CryptoSetup

	largestRcvdPacketNumber protocol.PacketNumber

	version protocol.VersionNumber
}

var _ unpacker = &packetUnpacker{}

func newPacketUnpacker(cs handshake.CryptoSetup, version protocol.VersionNumber) unpacker {
	return &packetUnpacker{
		cs:      cs,
		version: version,
	}
}

func (u *packetUnpacker) Unpack(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	r := bytes.NewReader(data)

	if hdr.IsLongHeader {
		if protocol.ByteCount(r.Len()) < hdr.Length {
			return nil, fmt.Errorf("packet length (%d bytes) is smaller than the expected length (%d bytes)", len(data)-int(hdr.ParsedLen()), hdr.Length)
		}
		data = data[:int(hdr.ParsedLen()+hdr.Length)]
		// TODO(#1312): implement parsing of compound packets
	}

	extHdr, err := hdr.ParseExtended(r, u.version)
	if err != nil {
		return nil, fmt.Errorf("error parsing extended header: %s", err)
	}
	extHdr.Raw = data[:len(data)-r.Len()]
	data = data[len(data)-r.Len():]

	pn := protocol.DecodePacketNumber(
		extHdr.PacketNumberLen,
		u.largestRcvdPacketNumber,
		extHdr.PacketNumber,
	)

	buf := *getPacketBuffer()
	buf = buf[:0]
	defer putPacketBuffer(&buf)

	var encLevel protocol.EncryptionLevel
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		encLevel = protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		encLevel = protocol.EncryptionHandshake
	default:
		if hdr.IsLongHeader {
			return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
		}
		encLevel = protocol.Encryption1RTT
	}
	opener, err := u.cs.GetOpener(encLevel)
	if err != nil {
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}
	decrypted, err := opener.Open(buf, data, pn, extHdr.Raw)
	if err != nil {
		return nil, qerr.Error(qerr.DecryptionFailure, err.Error())
	}

	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	u.largestRcvdPacketNumber = utils.MaxPacketNumber(u.largestRcvdPacketNumber, pn)

	fs, err := u.parseFrames(decrypted)
	if err != nil {
		return nil, err
	}

	return &unpackedPacket{
		hdr:             extHdr,
		packetNumber:    pn,
		encryptionLevel: encLevel,
		frames:          fs,
	}, nil
}

func (u *packetUnpacker) parseFrames(decrypted []byte) ([]wire.Frame, error) {
	r := bytes.NewReader(decrypted)
	if r.Len() == 0 {
		return nil, qerr.MissingPayload
	}

	fs := make([]wire.Frame, 0, 2)
	// Read all frames in the packet
	for {
		frame, err := wire.ParseNextFrame(r, u.version)
		if err != nil {
			return nil, err
		}
		if frame == nil {
			break
		}
		fs = append(fs, frame)
	}
	return fs, nil
}
