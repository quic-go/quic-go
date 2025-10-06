package qlog

import (
	"fmt"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog/jsontext"
)

func getPacketTypeFromEncryptionLevel(encLevel protocol.EncryptionLevel) logging.PacketType {
	switch encLevel {
	case protocol.EncryptionInitial:
		return logging.PacketTypeInitial
	case protocol.EncryptionHandshake:
		return logging.PacketTypeHandshake
	case protocol.Encryption0RTT:
		return logging.PacketType0RTT
	case protocol.Encryption1RTT:
		return logging.PacketType1RTT
	default:
		panic("unknown encryption level")
	}
}

type token struct {
	Raw []byte
}

func (t token) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("data"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", t.Raw)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// PacketHeader is a QUIC packet header.
// TODO: make this a long header
type packetHeader struct {
	PacketType       logging.PacketType
	KeyPhaseBit      logging.KeyPhaseBit
	PacketNumber     logging.PacketNumber
	Version          logging.Version
	SrcConnectionID  logging.ConnectionID
	DestConnectionID logging.ConnectionID
	Token            *token
}

func transformHeader(hdr *logging.Header) *packetHeader {
	ph := &packetHeader{
		PacketType:       logging.PacketTypeFromHeader(hdr),
		SrcConnectionID:  hdr.SrcConnectionID,
		DestConnectionID: hdr.DestConnectionID,
		Version:          hdr.Version,
	}
	if len(hdr.Token) > 0 {
		ph.Token = &token{Raw: hdr.Token}
	}
	return ph
}

func transformLongHeader(hdr *logging.ExtendedHeader) *packetHeader {
	ph := transformHeader(&hdr.Header)
	ph.PacketNumber = hdr.PacketNumber
	ph.KeyPhaseBit = hdr.KeyPhase
	return ph
}

func (ph packetHeader) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_type"))
	h.WriteToken(jsontext.String(packetType(ph.PacketType).String()))
	if ph.PacketType != logging.PacketTypeRetry {
		h.WriteToken(jsontext.String("packet_number"))
		h.WriteToken(jsontext.Int(int64(ph.PacketNumber)))
	}
	if ph.Version != 0 {
		h.WriteToken(jsontext.String("version"))
		h.WriteToken(jsontext.String(version(ph.Version).String()))
	}
	if ph.PacketType != logging.PacketType1RTT {
		h.WriteToken(jsontext.String("scil"))
		h.WriteToken(jsontext.Int(int64(ph.SrcConnectionID.Len())))
		if ph.SrcConnectionID.Len() > 0 {
			h.WriteToken(jsontext.String("scid"))
			h.WriteToken(jsontext.String(ph.SrcConnectionID.String()))
		}
	}
	h.WriteToken(jsontext.String("dcil"))
	h.WriteToken(jsontext.Int(int64(ph.DestConnectionID.Len())))
	if ph.DestConnectionID.Len() > 0 {
		h.WriteToken(jsontext.String("dcid"))
		h.WriteToken(jsontext.String(ph.DestConnectionID.String()))
	}
	if ph.KeyPhaseBit == logging.KeyPhaseZero || ph.KeyPhaseBit == logging.KeyPhaseOne {
		h.WriteToken(jsontext.String("key_phase_bit"))
		h.WriteToken(jsontext.String(ph.KeyPhaseBit.String()))
	}
	if ph.Token != nil {
		h.WriteToken(jsontext.String("token"))
		if err := ph.Token.Encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type packetHeaderVersionNegotiation struct {
	SrcConnectionID  logging.ArbitraryLenConnectionID
	DestConnectionID logging.ArbitraryLenConnectionID
}

func (phvn packetHeaderVersionNegotiation) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_type"))
	h.WriteToken(jsontext.String("version_negotiation"))
	h.WriteToken(jsontext.String("scil"))
	h.WriteToken(jsontext.Int(int64(phvn.SrcConnectionID.Len())))
	h.WriteToken(jsontext.String("scid"))
	h.WriteToken(jsontext.String(phvn.SrcConnectionID.String()))
	h.WriteToken(jsontext.String("dcil"))
	h.WriteToken(jsontext.Int(int64(phvn.DestConnectionID.Len())))
	h.WriteToken(jsontext.String("dcid"))
	h.WriteToken(jsontext.String(phvn.DestConnectionID.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// a minimal header that only outputs the packet type, and potentially a packet number
type packetHeaderWithType struct {
	PacketType   logging.PacketType
	PacketNumber logging.PacketNumber
}

func (phwt packetHeaderWithType) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_type"))
	h.WriteToken(jsontext.String(packetType(phwt.PacketType).String()))
	if phwt.PacketNumber != protocol.InvalidPacketNumber {
		h.WriteToken(jsontext.String("packet_number"))
		h.WriteToken(jsontext.Int(int64(phwt.PacketNumber)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// a minimal header that only outputs the packet type
type packetHeaderWithTypeAndPacketNumber struct {
	PacketType   logging.PacketType
	PacketNumber logging.PacketNumber
}

func (phwtpn packetHeaderWithTypeAndPacketNumber) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_type"))
	h.WriteToken(jsontext.String(packetType(phwtpn.PacketType).String()))
	h.WriteToken(jsontext.String("packet_number"))
	h.WriteToken(jsontext.Int(int64(phwtpn.PacketNumber)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type shortHeader struct {
	DestConnectionID logging.ConnectionID
	PacketNumber     logging.PacketNumber
	KeyPhaseBit      logging.KeyPhaseBit
}

func transformShortHeader(hdr *logging.ShortHeader) *shortHeader {
	return &shortHeader{
		DestConnectionID: hdr.DestConnectionID,
		PacketNumber:     hdr.PacketNumber,
		KeyPhaseBit:      hdr.KeyPhase,
	}
}

func (sh shortHeader) Encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_type"))
	h.WriteToken(jsontext.String(packetType(logging.PacketType1RTT).String()))
	if sh.DestConnectionID.Len() > 0 {
		h.WriteToken(jsontext.String("dcid"))
		h.WriteToken(jsontext.String(sh.DestConnectionID.String()))
	}
	h.WriteToken(jsontext.String("packet_number"))
	h.WriteToken(jsontext.Int(int64(sh.PacketNumber)))
	h.WriteToken(jsontext.String("key_phase_bit"))
	h.WriteToken(jsontext.String(sh.KeyPhaseBit.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}
