package quic

import (
	"bytes"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/handshake"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/qerr"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type headerDecryptor interface {
	DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
}

type headerParseError struct {
	err error
}

func (e *headerParseError) Unwrap() error {
	return e.err
}

func (e *headerParseError) Error() string {
	return e.err.Error()
}

type unpackedPacket struct {
	hdr             *wire.ExtendedHeader
	encryptionLevel protocol.EncryptionLevel
	data            []byte
}

// The packetUnpacker unpacks QUIC packets.
type packetUnpacker struct {
	cs handshake.CryptoSetup

	shortHdrConnIDLen int
	version           protocol.VersionNumber
}

var _ unpacker = &packetUnpacker{}

func newPacketUnpacker(cs handshake.CryptoSetup, shortHdrConnIDLen int, version protocol.VersionNumber) unpacker {
	return &packetUnpacker{
		cs:                cs,
		shortHdrConnIDLen: shortHdrConnIDLen,
		version:           version,
	}
}

// UnpackLongHeader unpacks a Long Header packet.
// If the reserved bits are invalid, the error is wire.ErrInvalidReservedBits.
// If any other error occurred when parsing the header, the error is of type headerParseError.
// If decrypting the payload fails for any reason, the error is the error returned by the AEAD.
func (u *packetUnpacker) UnpackLongHeader(hdr *wire.Header, rcvTime time.Time, data []byte) (*unpackedPacket, error) {
	var encLevel protocol.EncryptionLevel
	var extHdr *wire.ExtendedHeader
	var decrypted []byte
	//nolint:exhaustive // Retry packets can't be unpacked.
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
	case protocol.PacketType0RTT:
		encLevel = protocol.Encryption0RTT
		opener, err := u.cs.Get0RTTOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackLongHeaderPacket(opener, hdr, data)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
	}

	if len(decrypted) == 0 {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "empty packet",
		}
	}

	return &unpackedPacket{
		hdr:             extHdr,
		encryptionLevel: encLevel,
		data:            decrypted,
	}, nil
}

func (u *packetUnpacker) UnpackShortHeader(rcvTime time.Time, data []byte) (*wire.ShortHeader, []byte, error) {
	opener, err := u.cs.Get1RTTOpener()
	if err != nil {
		return nil, nil, err
	}
	hdr, decrypted, err := u.unpackShortHeaderPacket(opener, rcvTime, data)
	if err != nil {
		return nil, nil, err
	}
	if len(decrypted) == 0 {
		return nil, nil, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "empty packet",
		}
	}
	return hdr, decrypted, nil
}

func (u *packetUnpacker) unpackLongHeaderPacket(opener handshake.LongHeaderOpener, hdr *wire.Header, data []byte) (*wire.ExtendedHeader, []byte, error) {
	extHdr, parseErr := u.unpackLongHeader(opener, hdr, data)
	// If the reserved bits are set incorrectly, we still need to continue unpacking.
	// This avoids a timing side-channel, which otherwise might allow an attacker
	// to gain information about the header encryption.
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, nil, parseErr
	}
	extHdrLen := extHdr.ParsedLen()
	extHdr.PacketNumber = opener.DecodePacketNumber(extHdr.PacketNumber, extHdr.PacketNumberLen)
	decrypted, err := opener.Open(data[extHdrLen:extHdrLen], data[extHdrLen:], extHdr.PacketNumber, data[:extHdrLen])
	if err != nil {
		return nil, nil, err
	}
	if parseErr != nil {
		return nil, nil, parseErr
	}
	return extHdr, decrypted, nil
}

func (u *packetUnpacker) unpackShortHeaderPacket(opener handshake.ShortHeaderOpener, rcvTime time.Time, data []byte) (*wire.ShortHeader, []byte, error) {
	hdr, parseErr := u.unpackShortHeader(opener, data)
	// If the reserved bits are set incorrectly, we still need to continue unpacking.
	// This avoids a timing side-channel, which otherwise might allow an attacker
	// to gain information about the header encryption.
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, nil, &headerParseError{parseErr}
	}
	hdr.PacketNumber = opener.DecodePacketNumber(hdr.PacketNumber, hdr.PacketNumberLen)
	l := hdr.Len()
	decrypted, err := opener.Open(data[l:l], data[l:], rcvTime, hdr.PacketNumber, hdr.KeyPhase, data[:l])
	if err != nil {
		return nil, nil, err
	}
	return hdr, decrypted, parseErr
}

func (u *packetUnpacker) unpackShortHeader(hd headerDecryptor, data []byte) (*wire.ShortHeader, error) {
	hdrLen := 1 /* first header byte */ + u.shortHdrConnIDLen
	if len(data) < hdrLen+4+16 {
		return nil, fmt.Errorf("packet too small, expected at least 20 bytes after the header, got %d", len(data)-hdrLen)
	}
	origPNBytes := make([]byte, 4)
	copy(origPNBytes, data[hdrLen:hdrLen+4])
	// 2. decrypt the header, assuming a 4 byte packet number
	hd.DecryptHeader(
		data[hdrLen+4:hdrLen+4+16],
		&data[0],
		data[hdrLen:hdrLen+4],
	)
	// 3. parse the header (and learn the actual length of the packet number)
	hdr, parseErr := wire.ParseShortHeader(data, u.shortHdrConnIDLen)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if hdr.PacketNumberLen != protocol.PacketNumberLen4 {
		copy(data[hdrLen+int(hdr.PacketNumberLen):hdrLen+4], origPNBytes[int(hdr.PacketNumberLen):])
	}
	return hdr, parseErr
}

// The error is either nil, a wire.ErrInvalidReservedBits or of type headerParseError.
func (u *packetUnpacker) unpackLongHeader(hd headerDecryptor, hdr *wire.Header, data []byte) (*wire.ExtendedHeader, error) {
	extHdr, err := unpackLongHeader(hd, hdr, data, u.version)
	if err != nil && err != wire.ErrInvalidReservedBits {
		return nil, &headerParseError{err: err}
	}
	return extHdr, err
}

func unpackLongHeader(hd headerDecryptor, hdr *wire.Header, data []byte, version protocol.VersionNumber) (*wire.ExtendedHeader, error) {
	r := bytes.NewReader(data)

	hdrLen := hdr.ParsedLen()
	if protocol.ByteCount(len(data)) < hdrLen+4+16 {
		//nolint:stylecheck
		return nil, fmt.Errorf("Packet too small. Expected at least 20 bytes after the header, got %d", protocol.ByteCount(len(data))-hdrLen)
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
	extHdr, parseErr := hdr.ParseExtended(r, version)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if extHdr.PacketNumberLen != protocol.PacketNumberLen4 {
		copy(data[extHdr.ParsedLen():hdrLen+4], origPNBytes[int(extHdr.PacketNumberLen):])
	}
	return extHdr, parseErr
}
