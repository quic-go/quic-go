package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/lucas-clemente/quic-go/internal/qerr"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

type transportParameterID uint16

const (
	originalConnectionIDParameterID           transportParameterID = 0x0
	idleTimeoutParameterID                    transportParameterID = 0x1
	statelessResetTokenParameterID            transportParameterID = 0x2
	maxPacketSizeParameterID                  transportParameterID = 0x3
	initialMaxDataParameterID                 transportParameterID = 0x4
	initialMaxStreamDataBidiLocalParameterID  transportParameterID = 0x5
	initialMaxStreamDataBidiRemoteParameterID transportParameterID = 0x6
	initialMaxStreamDataUniParameterID        transportParameterID = 0x7
	initialMaxStreamsBidiParameterID          transportParameterID = 0x8
	initialMaxStreamsUniParameterID           transportParameterID = 0x9
	ackDelayExponentParameterID               transportParameterID = 0xa
	maxAckDelayParameterID                    transportParameterID = 0xb
	disableMigrationParameterID               transportParameterID = 0xc
	preferredAddressParamaterID               transportParameterID = 0xd
	activeConnectionIDLimitParameterID        transportParameterID = 0xe
)

// PreferredAddress is the value encoding in the preferred_address transport parameter
type PreferredAddress struct {
	IPv4                net.IP
	IPv4Port            uint16
	IPv6                net.IP
	IPv6Port            uint16
	ConnectionID        protocol.ConnectionID
	StatelessResetToken [16]byte
}

// TransportParameters are parameters sent to the peer during the handshake
type TransportParameters struct {
	InitialMaxStreamDataBidiLocal  protocol.ByteCount
	InitialMaxStreamDataBidiRemote protocol.ByteCount
	InitialMaxStreamDataUni        protocol.ByteCount
	InitialMaxData                 protocol.ByteCount

	MaxAckDelay      time.Duration
	AckDelayExponent uint8

	DisableMigration bool

	MaxPacketSize protocol.ByteCount

	MaxUniStreamNum  protocol.StreamNum
	MaxBidiStreamNum protocol.StreamNum

	IdleTimeout time.Duration

	PreferredAddress *PreferredAddress

	StatelessResetToken     *[16]byte
	OriginalConnectionID    protocol.ConnectionID
	ActiveConnectionIDLimit uint64
}

// Unmarshal the transport parameters
func (p *TransportParameters) Unmarshal(data []byte, sentBy protocol.Perspective) error {
	if err := p.unmarshal(data, sentBy); err != nil {
		return qerr.Error(qerr.TransportParameterError, err.Error())
	}
	return nil
}

func (p *TransportParameters) unmarshal(data []byte, sentBy protocol.Perspective) error {
	if len(data) < 2 {
		return errors.New("transport parameter data too short")
	}
	length := binary.BigEndian.Uint16(data[:2])
	if len(data)-2 < int(length) {
		return fmt.Errorf("expected transport parameters to be %d bytes long, have %d", length, len(data)-2)
	}

	// needed to check that every parameter is only sent at most once
	var parameterIDs []transportParameterID

	var readAckDelayExponent bool
	var readMaxAckDelay bool

	r := bytes.NewReader(data[2:])
	for r.Len() >= 4 {
		paramIDInt, _ := utils.BigEndian.ReadUint16(r)
		paramID := transportParameterID(paramIDInt)
		paramLen, _ := utils.BigEndian.ReadUint16(r)
		parameterIDs = append(parameterIDs, paramID)
		switch paramID {
		case ackDelayExponentParameterID:
			readAckDelayExponent = true
			if err := p.readNumericTransportParameter(r, paramID, int(paramLen)); err != nil {
				return err
			}
		case maxAckDelayParameterID:
			readMaxAckDelay = true
			if err := p.readNumericTransportParameter(r, paramID, int(paramLen)); err != nil {
				return err
			}
		case initialMaxStreamDataBidiLocalParameterID,
			initialMaxStreamDataBidiRemoteParameterID,
			initialMaxStreamDataUniParameterID,
			initialMaxDataParameterID,
			initialMaxStreamsBidiParameterID,
			initialMaxStreamsUniParameterID,
			idleTimeoutParameterID,
			maxPacketSizeParameterID,
			activeConnectionIDLimitParameterID:
			if err := p.readNumericTransportParameter(r, paramID, int(paramLen)); err != nil {
				return err
			}
		default:
			if r.Len() < int(paramLen) {
				return fmt.Errorf("remaining length (%d) smaller than parameter length (%d)", r.Len(), paramLen)
			}
			switch paramID {
			case preferredAddressParamaterID:
				if sentBy == protocol.PerspectiveClient {
					return errors.New("client sent a preferred_address")
				}
				if err := p.readPreferredAddress(r, int(paramLen)); err != nil {
					return err
				}
			case disableMigrationParameterID:
				if paramLen != 0 {
					return fmt.Errorf("wrong length for disable_migration: %d (expected empty)", paramLen)
				}
				p.DisableMigration = true
			case statelessResetTokenParameterID:
				if sentBy == protocol.PerspectiveClient {
					return errors.New("client sent a stateless_reset_token")
				}
				if paramLen != 16 {
					return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", paramLen)
				}
				var token [16]byte
				r.Read(token[:])
				p.StatelessResetToken = &token
			case originalConnectionIDParameterID:
				if sentBy == protocol.PerspectiveClient {
					return errors.New("client sent an original_connection_id")
				}
				p.OriginalConnectionID, _ = protocol.ReadConnectionID(r, int(paramLen))
			default:
				r.Seek(int64(paramLen), io.SeekCurrent)
			}
		}
	}

	if !readAckDelayExponent {
		p.AckDelayExponent = protocol.DefaultAckDelayExponent
	}
	if !readMaxAckDelay {
		p.MaxAckDelay = protocol.DefaultMaxAckDelay
	}
	if p.MaxPacketSize == 0 {
		p.MaxPacketSize = protocol.MaxByteCount
	}

	// check that every transport parameter was sent at most once
	sort.Slice(parameterIDs, func(i, j int) bool { return parameterIDs[i] < parameterIDs[j] })
	for i := 0; i < len(parameterIDs)-1; i++ {
		if parameterIDs[i] == parameterIDs[i+1] {
			return fmt.Errorf("received duplicate transport parameter %#x", parameterIDs[i])
		}
	}

	if r.Len() != 0 {
		return fmt.Errorf("should have read all data. Still have %d bytes", r.Len())
	}
	return nil
}

func (p *TransportParameters) readPreferredAddress(r *bytes.Reader, expectedLen int) error {
	remainingLen := r.Len()
	pa := &PreferredAddress{}
	ipv4 := make([]byte, 4)
	if _, err := io.ReadFull(r, ipv4); err != nil {
		return err
	}
	pa.IPv4 = net.IP(ipv4)
	port, err := utils.BigEndian.ReadUint16(r)
	if err != nil {
		return err
	}
	pa.IPv4Port = port
	ipv6 := make([]byte, 16)
	if _, err := io.ReadFull(r, ipv6); err != nil {
		return err
	}
	pa.IPv6 = net.IP(ipv6)
	port, err = utils.BigEndian.ReadUint16(r)
	if err != nil {
		return err
	}
	pa.IPv6Port = port
	connIDLen, err := r.ReadByte()
	if err != nil {
		return err
	}
	connID, err := protocol.ReadConnectionID(r, int(connIDLen))
	if err != nil {
		return err
	}
	pa.ConnectionID = connID
	if _, err := io.ReadFull(r, pa.StatelessResetToken[:]); err != nil {
		return err
	}
	if bytesRead := remainingLen - r.Len(); bytesRead != expectedLen {
		return fmt.Errorf("expected preferred_address to be %d long, read %d bytes", expectedLen, bytesRead)
	}
	p.PreferredAddress = pa
	return nil
}

func (p *TransportParameters) readNumericTransportParameter(
	r *bytes.Reader,
	paramID transportParameterID,
	expectedLen int,
) error {
	remainingLen := r.Len()
	val, err := utils.ReadVarInt(r)
	if err != nil {
		return fmt.Errorf("error while reading transport parameter %d: %s", paramID, err)
	}
	if remainingLen-r.Len() != expectedLen {
		return fmt.Errorf("inconsistent transport parameter length for %d", paramID)
	}
	switch paramID {
	case initialMaxStreamDataBidiLocalParameterID:
		p.InitialMaxStreamDataBidiLocal = protocol.ByteCount(val)
	case initialMaxStreamDataBidiRemoteParameterID:
		p.InitialMaxStreamDataBidiRemote = protocol.ByteCount(val)
	case initialMaxStreamDataUniParameterID:
		p.InitialMaxStreamDataUni = protocol.ByteCount(val)
	case initialMaxDataParameterID:
		p.InitialMaxData = protocol.ByteCount(val)
	case initialMaxStreamsBidiParameterID:
		p.MaxBidiStreamNum = protocol.StreamNum(val)
	case initialMaxStreamsUniParameterID:
		p.MaxUniStreamNum = protocol.StreamNum(val)
	case idleTimeoutParameterID:
		p.IdleTimeout = utils.MaxDuration(protocol.MinRemoteIdleTimeout, time.Duration(val)*time.Millisecond)
	case maxPacketSizeParameterID:
		if val < 1200 {
			return fmt.Errorf("invalid value for max_packet_size: %d (minimum 1200)", val)
		}
		p.MaxPacketSize = protocol.ByteCount(val)
	case ackDelayExponentParameterID:
		if val > protocol.MaxAckDelayExponent {
			return fmt.Errorf("invalid value for ack_delay_exponent: %d (maximum %d)", val, protocol.MaxAckDelayExponent)
		}
		p.AckDelayExponent = uint8(val)
	case maxAckDelayParameterID:
		maxAckDelay := time.Duration(val) * time.Millisecond
		if maxAckDelay >= protocol.MaxMaxAckDelay {
			return fmt.Errorf("invalid value for max_ack_delay: %dms (maximum %dms)", maxAckDelay/time.Millisecond, (protocol.MaxMaxAckDelay-time.Millisecond)/time.Millisecond)
		}
		if maxAckDelay < 0 {
			maxAckDelay = utils.InfDuration
		}
		p.MaxAckDelay = maxAckDelay
	case activeConnectionIDLimitParameterID:
		p.ActiveConnectionIDLimit = val
	default:
		return fmt.Errorf("TransportParameter BUG: transport parameter %d not found", paramID)
	}
	return nil
}

// Marshal the transport parameters
func (p *TransportParameters) Marshal() []byte {
	b := &bytes.Buffer{}
	b.Write([]byte{0, 0}) // length. Will be replaced later

	//add a greased value
	utils.BigEndian.WriteUint16(b, uint16(27+31*rand.Intn(100)))
	length := rand.Intn(16)
	randomData := make([]byte, length)
	rand.Read(randomData)
	utils.BigEndian.WriteUint16(b, uint16(length))
	b.Write(randomData)

	// initial_max_stream_data_bidi_local
	p.marshalVarintParam(b, initialMaxStreamDataBidiLocalParameterID, uint64(p.InitialMaxStreamDataBidiLocal))
	// initial_max_stream_data_bidi_remote
	p.marshalVarintParam(b, initialMaxStreamDataBidiRemoteParameterID, uint64(p.InitialMaxStreamDataBidiRemote))
	// initial_max_stream_data_uni
	p.marshalVarintParam(b, initialMaxStreamDataUniParameterID, uint64(p.InitialMaxStreamDataUni))
	// initial_max_data
	p.marshalVarintParam(b, initialMaxDataParameterID, uint64(p.InitialMaxData))
	// initial_max_bidi_streams
	p.marshalVarintParam(b, initialMaxStreamsBidiParameterID, uint64(p.MaxBidiStreamNum))
	// initial_max_uni_streams
	p.marshalVarintParam(b, initialMaxStreamsUniParameterID, uint64(p.MaxUniStreamNum))
	// idle_timeout
	p.marshalVarintParam(b, idleTimeoutParameterID, uint64(p.IdleTimeout/time.Millisecond))
	// max_packet_size
	p.marshalVarintParam(b, maxPacketSizeParameterID, uint64(protocol.MaxReceivePacketSize))
	// max_ack_delay
	// Only send it if is different from the default value.
	if p.MaxAckDelay != protocol.DefaultMaxAckDelay {
		p.marshalVarintParam(b, maxAckDelayParameterID, uint64(p.MaxAckDelay/time.Millisecond))
	}
	// ack_delay_exponent
	// Only send it if is different from the default value.
	if p.AckDelayExponent != protocol.DefaultAckDelayExponent {
		p.marshalVarintParam(b, ackDelayExponentParameterID, uint64(p.AckDelayExponent))
	}
	// disable_migration
	if p.DisableMigration {
		utils.BigEndian.WriteUint16(b, uint16(disableMigrationParameterID))
		utils.BigEndian.WriteUint16(b, 0)
	}
	if p.StatelessResetToken != nil {
		utils.BigEndian.WriteUint16(b, uint16(statelessResetTokenParameterID))
		utils.BigEndian.WriteUint16(b, 16)
		b.Write(p.StatelessResetToken[:])
	}
	if p.PreferredAddress != nil {
		utils.BigEndian.WriteUint16(b, uint16(preferredAddressParamaterID))
		utils.BigEndian.WriteUint16(b, 4+2+16+2+1+uint16(p.PreferredAddress.ConnectionID.Len())+16)
		ipv4 := p.PreferredAddress.IPv4
		b.Write(ipv4[len(ipv4)-4:])
		utils.BigEndian.WriteUint16(b, p.PreferredAddress.IPv4Port)
		b.Write(p.PreferredAddress.IPv6)
		utils.BigEndian.WriteUint16(b, p.PreferredAddress.IPv6Port)
		b.WriteByte(uint8(p.PreferredAddress.ConnectionID.Len()))
		b.Write(p.PreferredAddress.ConnectionID.Bytes())
		b.Write(p.PreferredAddress.StatelessResetToken[:])
	}
	if p.OriginalConnectionID.Len() > 0 {
		utils.BigEndian.WriteUint16(b, uint16(originalConnectionIDParameterID))
		utils.BigEndian.WriteUint16(b, uint16(p.OriginalConnectionID.Len()))
		b.Write(p.OriginalConnectionID.Bytes())
	}

	// active_connection_id_limit
	p.marshalVarintParam(b, activeConnectionIDLimitParameterID, p.ActiveConnectionIDLimit)

	data := b.Bytes()
	binary.BigEndian.PutUint16(data[:2], uint16(b.Len()-2))
	return data
}

func (p *TransportParameters) marshalVarintParam(b *bytes.Buffer, id transportParameterID, val uint64) {
	utils.BigEndian.WriteUint16(b, uint16(id))
	utils.BigEndian.WriteUint16(b, uint16(utils.VarIntLen(val)))
	utils.WriteVarInt(b, val)
}

// String returns a string representation, intended for logging.
func (p *TransportParameters) String() string {
	logString := "&handshake.TransportParameters{OriginalConnectionID: %s, InitialMaxStreamDataBidiLocal: %#x, InitialMaxStreamDataBidiRemote: %#x, InitialMaxStreamDataUni: %#x, InitialMaxData: %#x, MaxBidiStreamNum: %d, MaxUniStreamNum: %d, IdleTimeout: %s, AckDelayExponent: %d, MaxAckDelay: %s, ActiveConnectionIDLimit: %d"
	logParams := []interface{}{p.OriginalConnectionID, p.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataUni, p.InitialMaxData, p.MaxBidiStreamNum, p.MaxUniStreamNum, p.IdleTimeout, p.AckDelayExponent, p.MaxAckDelay, p.ActiveConnectionIDLimit}
	if p.StatelessResetToken != nil { // the client never sends a stateless reset token
		logString += ", StatelessResetToken: %#x"
		logParams = append(logParams, *p.StatelessResetToken)
	}
	logString += "}"
	return fmt.Sprintf(logString, logParams...)
}
