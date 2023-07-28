package transportparameters

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"

	"github.com/quic-go/quic-go/quicvarint"
)

const (
	// RFC IDs
	max_idle_timeout                    uint64 = 0x1
	max_udp_payload_size                uint64 = 0x3
	initial_max_data                    uint64 = 0x4
	initial_max_stream_data_bidi_local  uint64 = 0x5
	initial_max_stream_data_bidi_remote uint64 = 0x6
	initial_max_stream_data_uni         uint64 = 0x7
	initial_max_streams_bidi            uint64 = 0x8
	initial_max_streams_uni             uint64 = 0x9
	max_ack_delay                       uint64 = 0xb
	disable_active_migration            uint64 = 0xc
	active_connection_id_limit          uint64 = 0xe
	initial_source_connection_id        uint64 = 0xf
	version_information                 uint64 = 0x11 // RFC 9368
	padding                             uint64 = 0x15
	max_datagram_frame_size             uint64 = 0x20 // RFC 9221
	grease_quic_bit                     uint64 = 0x2ab2

	// Legacy IDs from draft
	version_information_legacy uint64 = 0xff73db // draft-ietf-quic-version-negotiation-13 and early
)

type TransportParameters []TransportParameter

func (tps TransportParameters) Marshal() []byte {
	var b []byte
	for _, tp := range tps {
		b = quicvarint.Append(b, tp.ID())
		b = quicvarint.Append(b, uint64(len(tp.Value())))
		b = append(b, tp.Value()...)
	}
	return b
}

// TransportParameter represents a QUIC transport parameter.
//
// Caller will write the following to the wire:
//
//	var b []byte
//	b = quicvarint.Append(b, ID())
//	b = quicvarint.Append(b, len(Value()))
//	b = append(b, Value())
//
// Therefore Value() should return the exact bytes to be written to the wire AFTER the length field,
// i.e., the bytes MAY be a Variable Length Integer per RFC depending on the type of the transport
// parameter, but MUST NOT including the length field unless the parameter is defined so.
type TransportParameter interface {
	ID() uint64
	Value() []byte
}

type GREASE struct {
	IdOverride    uint64 // if set to a valid GREASE ID, use this instead of randomly generated one.
	Length        uint16 // if len(ValueOverride) == 0, will generate random data of this size.
	ValueOverride []byte // if len(ValueOverride) > 0, use this instead of random bytes.
}

const (
	GREASE_MAX_MULTIPLIER = (0x3FFFFFFFFFFFFFFF - 27) / 31
)

// IsGREASEID returns true if id is a valid GREASE ID for
// transport parameters.
func (GREASE) IsGREASEID(id uint64) bool {
	return (id-27)%31 == 0
}

// GetGREASEID returns a random valid GREASE ID for transport parameters.
func (GREASE) GetGREASEID() uint64 {
	max := big.NewInt(GREASE_MAX_MULTIPLIER)

	randMultiply, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 27
	}

	return 27 + randMultiply.Uint64()*31
}

func (g *GREASE) ID() uint64 {
	if !g.IsGREASEID(g.IdOverride) {
		g.IdOverride = g.GetGREASEID()
	}
	return g.IdOverride
}

func (g *GREASE) Value() []byte {
	if len(g.ValueOverride) == 0 {
		g.ValueOverride = make([]byte, g.Length)
		rand.Read(g.ValueOverride)
	}
	return g.ValueOverride
}

type MaxIdleTimeout uint64 // in milliseconds

func (MaxIdleTimeout) ID() uint64 {
	return max_idle_timeout
}

func (m MaxIdleTimeout) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type MaxUDPPayloadSize uint64

func (MaxUDPPayloadSize) ID() uint64 {
	return max_udp_payload_size
}

func (m MaxUDPPayloadSize) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type InitialMaxData uint64

func (InitialMaxData) ID() uint64 {
	return initial_max_data
}

func (i InitialMaxData) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamDataBidiLocal uint64

func (InitialMaxStreamDataBidiLocal) ID() uint64 {
	return initial_max_stream_data_bidi_local
}

func (i InitialMaxStreamDataBidiLocal) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamDataBidiRemote uint64

func (InitialMaxStreamDataBidiRemote) ID() uint64 {
	return initial_max_stream_data_bidi_remote
}

func (i InitialMaxStreamDataBidiRemote) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamDataUni uint64

func (InitialMaxStreamDataUni) ID() uint64 {
	return initial_max_stream_data_uni
}

func (i InitialMaxStreamDataUni) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamsBidi uint64

func (InitialMaxStreamsBidi) ID() uint64 {
	return initial_max_streams_bidi
}

func (i InitialMaxStreamsBidi) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type InitialMaxStreamsUni uint64

func (InitialMaxStreamsUni) ID() uint64 {
	return initial_max_streams_uni
}

func (i InitialMaxStreamsUni) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(i))
}

type MaxAckDelay uint64

func (MaxAckDelay) ID() uint64 {
	return max_ack_delay
}

func (m MaxAckDelay) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type DisableActiveMigration struct{}

func (*DisableActiveMigration) ID() uint64 {
	return disable_active_migration
}

// Its Value MUST ALWAYS be empty.
func (*DisableActiveMigration) Value() []byte {
	return []byte{}
}

type ActiveConnectionIDLimit uint64

func (ActiveConnectionIDLimit) ID() uint64 {
	return active_connection_id_limit
}

func (a ActiveConnectionIDLimit) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(a))
}

type InitialSourceConnectionID []byte // if empty, will be set to the Connection ID used for the Initial packet.

func (InitialSourceConnectionID) ID() uint64 {
	return initial_source_connection_id
}

func (i InitialSourceConnectionID) Value() []byte {
	return []byte(i)
}

type VersionInformation struct {
	ChoosenVersion    uint32
	AvailableVersions []uint32 // Also known as "Other Versions" in early drafts.

	LegacyID bool // If true, use the legacy-assigned ID (0xff73db) instead of the RFC-assigned one (0x11).
}

const (
	VERSION_NEGOTIATION uint32 = 0x00000000 // rfc9000
	VERSION_1           uint32 = 0x00000001 // rfc9000
	VERSION_2           uint32 = 0x6b3343cf // rfc9369

	VERSION_GREASE uint32 = 0x0a0a0a0a // -> 0x?a?a?a?a
)

func (v *VersionInformation) ID() uint64 {
	if v.LegacyID {
		return version_information_legacy
	}
	return version_information
}

func (v *VersionInformation) Value() []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, v.ChoosenVersion)
	for _, version := range v.AvailableVersions {
		if version != VERSION_GREASE {
			b = binary.BigEndian.AppendUint32(b, version)
		} else {
			b = binary.BigEndian.AppendUint32(b, v.GetGREASEVersion())
		}
	}
	return b
}

func (*VersionInformation) GetGREASEVersion() uint32 {
	// get a random uint32
	max := big.NewInt(math.MaxUint32)
	randVal, err := rand.Int(rand.Reader, max)
	if err != nil {
		return VERSION_GREASE
	}

	return uint32(randVal.Uint64()&math.MaxUint32) | 0x0a0a0a0a // all GREASE versions are in 0x?a?a?a?a
}

type Padding []byte

func (Padding) ID() uint64 {
	return padding
}

func (p Padding) Value() []byte {
	return p
}

type MaxDatagramFrameSize uint64

func (MaxDatagramFrameSize) ID() uint64 {
	return max_datagram_frame_size
}

func (m MaxDatagramFrameSize) Value() []byte {
	return quicvarint.Append([]byte{}, uint64(m))
}

type GREASEQUICBit struct{}

func (*GREASEQUICBit) ID() uint64 {
	return grease_quic_bit
}

// Its Value MUST ALWAYS be empty.
func (*GREASEQUICBit) Value() []byte {
	return []byte{}
}
