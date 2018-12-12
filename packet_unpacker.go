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
	packetNumber    protocol.PacketNumber // the decoded packet number
	hdr             *wire.ExtendedHeader
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

func (u *packetUnpacker) Unpack(hdr *wire.Header, data []byte) (*unpackedPacket, error) {
	r := bytes.NewReader(data)
	extHdr, err := hdr.ParseExtended(r, u.version)
	if err != nil {
		return nil, fmt.Errorf("error parsing extended header: %s", err)
	}
	extHdr.Raw = data[:len(data)-r.Len()]
	data = data[len(data)-r.Len():]

	if hdr.IsLongHeader {
		if hdr.Length < protocol.ByteCount(extHdr.PacketNumberLen) {
			return nil, fmt.Errorf("packet length (%d bytes) shorter than packet number (%d bytes)", extHdr.Length, extHdr.PacketNumberLen)
		}
		if protocol.ByteCount(len(data))+protocol.ByteCount(extHdr.PacketNumberLen) < extHdr.Length {
			return nil, fmt.Errorf("packet length (%d bytes) is smaller than the expected length (%d bytes)", len(data)+int(extHdr.PacketNumberLen), extHdr.Length)
		}
		data = data[:int(extHdr.Length)-int(extHdr.PacketNumberLen)]
		// TODO(#1312): implement parsing of compound packets
	}

	pn := protocol.DecodePacketNumber(
		extHdr.PacketNumberLen,
		u.largestRcvdPacketNumber,
		extHdr.PacketNumber,
	)

	buf := *getPacketBuffer()
	buf = buf[:0]
	defer putPacketBuffer(&buf)

	var decrypted []byte
	var encryptionLevel protocol.EncryptionLevel
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		decrypted, err = u.aead.OpenInitial(buf, data, pn, extHdr.Raw)
		encryptionLevel = protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		decrypted, err = u.aead.OpenHandshake(buf, data, pn, extHdr.Raw)
		encryptionLevel = protocol.EncryptionHandshake
	default:
		if hdr.IsLongHeader {
			return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
		}
		decrypted, err = u.aead.Open1RTT(buf, data, pn, extHdr.Raw)
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
		hdr:             extHdr,
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
