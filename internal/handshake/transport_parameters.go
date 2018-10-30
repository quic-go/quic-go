package handshake

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type transportParameterID uint16

const (
	initialMaxStreamDataParameterID  transportParameterID = 0x0
	initialMaxDataParameterID        transportParameterID = 0x1
	initialMaxBidiStreamsParameterID transportParameterID = 0x2
	idleTimeoutParameterID           transportParameterID = 0x3
	maxPacketSizeParameterID         transportParameterID = 0x5
	statelessResetTokenParameterID   transportParameterID = 0x6
	initialMaxUniStreamsParameterID  transportParameterID = 0x8
	disableMigrationParameterID      transportParameterID = 0x9
)

// TransportParameters are parameters sent to the peer during the handshake
type TransportParameters struct {
	InitialMaxStreamData protocol.ByteCount
	InitialMaxData       protocol.ByteCount

	MaxPacketSize protocol.ByteCount

	MaxUniStreams  uint16
	MaxBidiStreams uint16

	IdleTimeout         time.Duration
	DisableMigration    bool
	StatelessResetToken []byte
}

func (p *TransportParameters) unmarshal(data []byte) error {
	// needed to check that every parameter is only sent at most once
	var parameterIDs []transportParameterID

	for len(data) >= 4 {
		paramID := transportParameterID(binary.BigEndian.Uint16(data[:2]))
		paramLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < paramLen {
			return fmt.Errorf("remaining length (%d) smaller than parameter length (%d)", len(data), paramLen)
		}
		parameterIDs = append(parameterIDs, paramID)
		switch paramID {
		case initialMaxStreamDataParameterID:
			if paramLen != 4 {
				return fmt.Errorf("wrong length for initial_max_stream_data: %d (expected 4)", paramLen)
			}
			p.InitialMaxStreamData = protocol.ByteCount(binary.BigEndian.Uint32(data[:4]))
		case initialMaxDataParameterID:
			if paramLen != 4 {
				return fmt.Errorf("wrong length for initial_max_data: %d (expected 4)", paramLen)
			}
			p.InitialMaxData = protocol.ByteCount(binary.BigEndian.Uint32(data[:4]))
		case initialMaxBidiStreamsParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for initial_max_stream_id_bidi: %d (expected 2)", paramLen)
			}
			p.MaxBidiStreams = binary.BigEndian.Uint16(data[:2])
		case initialMaxUniStreamsParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for initial_max_stream_id_uni: %d (expected 2)", paramLen)
			}
			p.MaxUniStreams = binary.BigEndian.Uint16(data[:2])
		case idleTimeoutParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for idle_timeout: %d (expected 2)", paramLen)
			}
			p.IdleTimeout = utils.MaxDuration(protocol.MinRemoteIdleTimeout, time.Duration(binary.BigEndian.Uint16(data[:2]))*time.Second)
		case maxPacketSizeParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for max_packet_size: %d (expected 2)", paramLen)
			}
			maxPacketSize := protocol.ByteCount(binary.BigEndian.Uint16(data[:2]))
			if maxPacketSize < 1200 {
				return fmt.Errorf("invalid value for max_packet_size: %d (minimum 1200)", maxPacketSize)
			}
			p.MaxPacketSize = maxPacketSize
		case disableMigrationParameterID:
			if paramLen != 0 {
				return fmt.Errorf("wrong length for disable_migration: %d (expected empty)", paramLen)
			}
			p.DisableMigration = true
		case statelessResetTokenParameterID:
			if paramLen != 16 {
				return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", paramLen)
			}
			p.StatelessResetToken = data[:16]
		}
		data = data[paramLen:]
	}

	// check that every transport parameter was sent at most once
	sort.Slice(parameterIDs, func(i, j int) bool { return parameterIDs[i] < parameterIDs[j] })
	for i := 0; i < len(parameterIDs)-1; i++ {
		if parameterIDs[i] == parameterIDs[i+1] {
			return fmt.Errorf("received duplicate transport parameter %#x", parameterIDs[i])
		}
	}

	if len(data) != 0 {
		return fmt.Errorf("should have read all data. Still have %d bytes", len(data))
	}
	return nil
}

func (p *TransportParameters) marshal(b *bytes.Buffer) {
	// initial_max_stream_data
	utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataParameterID))
	utils.BigEndian.WriteUint16(b, 4)
	utils.BigEndian.WriteUint32(b, uint32(p.InitialMaxStreamData))
	// initial_max_data
	utils.BigEndian.WriteUint16(b, uint16(initialMaxDataParameterID))
	utils.BigEndian.WriteUint16(b, 4)
	utils.BigEndian.WriteUint32(b, uint32(p.InitialMaxData))
	// initial_max_bidi_streams
	utils.BigEndian.WriteUint16(b, uint16(initialMaxBidiStreamsParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, p.MaxBidiStreams)
	// initial_max_uni_streams
	utils.BigEndian.WriteUint16(b, uint16(initialMaxUniStreamsParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, p.MaxUniStreams)
	// idle_timeout
	utils.BigEndian.WriteUint16(b, uint16(idleTimeoutParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, uint16(p.IdleTimeout/time.Second))
	// max_packet_size
	utils.BigEndian.WriteUint16(b, uint16(maxPacketSizeParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, uint16(protocol.MaxReceivePacketSize))
	// disable_migration
	if p.DisableMigration {
		utils.BigEndian.WriteUint16(b, uint16(disableMigrationParameterID))
		utils.BigEndian.WriteUint16(b, 0)
	}
	if len(p.StatelessResetToken) > 0 {
		utils.BigEndian.WriteUint16(b, uint16(statelessResetTokenParameterID))
		utils.BigEndian.WriteUint16(b, uint16(len(p.StatelessResetToken))) // should always be 16 bytes
		b.Write(p.StatelessResetToken)
	}
}

// String returns a string representation, intended for logging.
func (p *TransportParameters) String() string {
	return fmt.Sprintf("&handshake.TransportParameters{InitialMaxStreamData: %#x, InitialMaxData: %#x, MaxBidiStreams: %d, MaxUniStreams: %d, IdleTimeout: %s}", p.InitialMaxStreamData, p.InitialMaxData, p.MaxBidiStreams, p.MaxUniStreams, p.IdleTimeout)
}
