package quic

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type unpackedPacket struct {
	packetNumber    protocol.PacketNumber
	encryptionLevel protocol.EncryptionLevel
	frames          []wire.Frame
}

type quicAEAD interface {
	OpenInitial(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error)
	OpenHandshake(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error)
	Open1RTT(dst, src []byte, pn protocol.PacketNumber, ad []byte) ([]byte, error)
}

// The packetUnpacker unpacks QUIC packets.
type packetUnpacker struct {
	aead quicAEAD

	largestRcvdPacketNumber protocol.PacketNumber

	version protocol.VersionNumber
}

var _ unpacker = &packetUnpacker{}

func newPacketUnpacker(aead quicAEAD, version protocol.VersionNumber) unpacker {
	return &packetUnpacker{
		aead:    aead,
		version: version,
	}
}

func (u *packetUnpacker) Unpack(headerBinary []byte, hdr *wire.ExtendedHeader, data []byte) (*unpackedPacket, error) {
	pn := protocol.DecodePacketNumber(
		hdr.PacketNumberLen,
		u.largestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	buf := *getPacketBuffer()
	buf = buf[:0]
	defer putPacketBuffer(&buf)

	var decrypted []byte
	var encryptionLevel protocol.EncryptionLevel
	var err error
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		decrypted, err = u.aead.OpenInitial(buf, data, pn, headerBinary)
		encryptionLevel = protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		decrypted, err = u.aead.OpenHandshake(buf, data, pn, headerBinary)
		encryptionLevel = protocol.EncryptionHandshake
	default:
		if hdr.IsLongHeader {
			return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
		}
		decrypted, err = u.aead.Open1RTT(buf, data, pn, headerBinary)
		encryptionLevel = protocol.Encryption1RTT
	}
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
		packetNumber:    pn,
		encryptionLevel: encryptionLevel,
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
