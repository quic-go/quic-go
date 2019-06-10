package quic

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type headerDecryptor interface {
	DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
}

type unpackedPacket struct {
	packetNumber    protocol.PacketNumber // the decoded packet number
	hdr             *wire.ExtendedHeader
	encryptionLevel protocol.EncryptionLevel
	data            []byte
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
	var encLevel protocol.EncryptionLevel
	var extHdr *wire.ExtendedHeader
	var decrypted []byte
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		encLevel = protocol.EncryptionInitial
		opener, err := u.cs.GetInitialOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackLongHeaderPacket(opener, hdr, data)
		if err != nil {
			return nil, err
		}
	case protocol.PacketTypeHandshake:
		encLevel = protocol.EncryptionHandshake
		opener, err := u.cs.GetHandshakeOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackLongHeaderPacket(opener, hdr, data)
		if err != nil {
			return nil, err
		}
	default:
		if hdr.IsLongHeader {
			return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
		}
		encLevel = protocol.Encryption1RTT
		opener, err := u.cs.Get1RTTOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackShortHeaderPacket(opener, hdr, data)
		if err != nil {
			return nil, err
		}
	}

	// Only do this after decrypting, so we are sure the packet is not attacker-controlled
	u.largestRcvdPacketNumber = utils.MaxPacketNumber(u.largestRcvdPacketNumber, extHdr.PacketNumber)

	return &unpackedPacket{
		hdr:             extHdr,
		packetNumber:    extHdr.PacketNumber,
		encryptionLevel: encLevel,
		data:            decrypted,
	}, nil
}

func (u *packetUnpacker) unpackLongHeaderPacket(opener handshake.LongHeaderOpener, hdr *wire.Header, data []byte) (*wire.ExtendedHeader, []byte, error) {
	extHdr, err := u.unpack(opener, hdr, data)
	if err != nil {
		return nil, nil, err
	}
	extHdrLen := extHdr.GetLength(u.version)
	decrypted, err := opener.Open(data[extHdrLen:extHdrLen], data[extHdrLen:], extHdr.PacketNumber, data[:extHdrLen])
	if err != nil {
		return nil, nil, err
	}
	return extHdr, decrypted, nil
}

func (u *packetUnpacker) unpackShortHeaderPacket(opener handshake.ShortHeaderOpener, hdr *wire.Header, data []byte) (*wire.ExtendedHeader, []byte, error) {
	extHdr, err := u.unpack(opener, hdr, data)
	if err != nil {
		return nil, nil, err
	}
	extHdrLen := extHdr.GetLength(u.version)
	decrypted, err := opener.Open(data[extHdrLen:extHdrLen], data[extHdrLen:], extHdr.PacketNumber, extHdr.KeyPhase, data[:extHdrLen])
	if err != nil {
		return nil, nil, err
	}
	return extHdr, decrypted, nil
}

func (u *packetUnpacker) unpack(hd headerDecryptor, hdr *wire.Header, data []byte) (*wire.ExtendedHeader, error) {
	r := bytes.NewReader(data)

	hdrLen := int(hdr.ParsedLen())
	if len(data) < hdrLen+4+16 {
		return nil, fmt.Errorf("Packet too small. Expected at least 20 bytes after the header, got %d", len(data)-hdrLen)
	}
	// The packet number can be up to 4 bytes long, but we won't know the length until we decrypt it.
	// 1. save a copy of the 4 bytes
	origPNBytes := make([]byte, 4)
	copy(origPNBytes, data[hdrLen:hdrLen+4])
	// 2. decrypt the header, assuming a 4 byte packet number
	hd.DecryptHeader(
		data[hdrLen+4:hdrLen+4+16],
		&data[0],
		data[hdrLen:hdrLen+4],
	)
	// 3. parse the header (and learn the actual length of the packet number)
	extHdr, err := hdr.ParseExtended(r, u.version)
	if err != nil {
		return nil, fmt.Errorf("error parsing extended header: %s", err)
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if extHdr.PacketNumberLen != protocol.PacketNumberLen4 {
		copy(data[extHdr.GetLength(u.version):hdrLen+4], origPNBytes[int(extHdr.PacketNumberLen):])
	}

	extHdr.PacketNumber = protocol.DecodePacketNumber(
		extHdr.PacketNumberLen,
		u.largestRcvdPacketNumber,
		extHdr.PacketNumber,
	)
	return extHdr, nil
}
