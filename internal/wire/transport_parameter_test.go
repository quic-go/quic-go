package wire

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	mrand "math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func getRandomValueUpTo(max uint64) uint64 {
	maxVals := []uint64{math.MaxUint8 / 4, math.MaxUint16 / 4, math.MaxUint32 / 4, math.MaxUint64 / 4}
	return mrand.Uint64N(min(max, maxVals[mrand.IntN(4)]))
}

func getRandomValue() uint64 { return getRandomValueUpTo(quicvarint.Max) }

func appendInitialSourceConnectionID(b []byte) []byte {
	b = quicvarint.Append(b, uint64(initialSourceConnectionIDParameterID))
	b = quicvarint.Append(b, 6)
	return append(b, []byte("foobar")...)
}

func TestTransportParametersStringRepresentation(t *testing.T) {
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	p := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   1234,
		InitialMaxStreamDataBidiRemote:  2345,
		InitialMaxStreamDataUni:         3456,
		InitialMaxData:                  4567,
		MaxBidiStreamNum:                1337,
		MaxUniStreamNum:                 7331,
		MaxIdleTimeout:                  42 * time.Second,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		RetrySourceConnectionID:         &rcid,
		AckDelayExponent:                14,
		MaxAckDelay:                     37 * time.Millisecond,
		StatelessResetToken:             &protocol.StatelessResetToken{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
		ActiveConnectionIDLimit:         123,
		MaxDatagramFrameSize:            876,
	}
	expected := "&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: decafbad, RetrySourceConnectionID: deadc0de, InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37ms, ActiveConnectionIDLimit: 123, StatelessResetToken: 0x112233445566778899aabbccddeeff00, MaxDatagramFrameSize: 876}"
	require.Equal(t, expected, p.String())
}

func TestTransportParametersStringRepresentationWithoutOptionalFields(t *testing.T) {
	p := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   1234,
		InitialMaxStreamDataBidiRemote:  2345,
		InitialMaxStreamDataUni:         3456,
		InitialMaxData:                  4567,
		MaxBidiStreamNum:                1337,
		MaxUniStreamNum:                 7331,
		MaxIdleTimeout:                  42 * time.Second,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{}),
		AckDelayExponent:                14,
		MaxAckDelay:                     37 * time.Second,
		ActiveConnectionIDLimit:         89,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
	}
	expected := "&wire.TransportParameters{OriginalDestinationConnectionID: deadbeef, InitialSourceConnectionID: (empty), InitialMaxStreamDataBidiLocal: 1234, InitialMaxStreamDataBidiRemote: 2345, InitialMaxStreamDataUni: 3456, InitialMaxData: 4567, MaxBidiStreamNum: 1337, MaxUniStreamNum: 7331, MaxIdleTimeout: 42s, AckDelayExponent: 14, MaxAckDelay: 37s, ActiveConnectionIDLimit: 89}"
	require.Equal(t, expected, p.String())
}

func TestMarshalAndUnmarshalTransportParameters(t *testing.T) {
	var token protocol.StatelessResetToken
	rand.Read(token[:])
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataUni:         protocol.ByteCount(getRandomValue()),
		InitialMaxData:                  protocol.ByteCount(getRandomValue()),
		MaxIdleTimeout:                  0xcafe * time.Second,
		MaxBidiStreamNum:                protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		MaxUniStreamNum:                 protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		DisableActiveMigration:          true,
		StatelessResetToken:             &token,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		RetrySourceConnectionID:         &rcid,
		AckDelayExponent:                13,
		MaxAckDelay:                     42 * time.Millisecond,
		ActiveConnectionIDLimit:         2 + getRandomValueUpTo(quicvarint.Max-2),
		MaxUDPPayloadSize:               1200 + protocol.ByteCount(getRandomValueUpTo(quicvarint.Max-1200)),
		MaxDatagramFrameSize:            protocol.ByteCount(getRandomValue()),
	}
	data := params.Marshal(protocol.PerspectiveServer)

	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.Equal(t, params.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiLocal)
	require.Equal(t, params.InitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataBidiRemote)
	require.Equal(t, params.InitialMaxStreamDataUni, p.InitialMaxStreamDataUni)
	require.Equal(t, params.InitialMaxData, p.InitialMaxData)
	require.Equal(t, params.MaxUniStreamNum, p.MaxUniStreamNum)
	require.Equal(t, params.MaxBidiStreamNum, p.MaxBidiStreamNum)
	require.Equal(t, params.MaxIdleTimeout, p.MaxIdleTimeout)
	require.Equal(t, params.DisableActiveMigration, p.DisableActiveMigration)
	require.Equal(t, params.StatelessResetToken, p.StatelessResetToken)
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}), p.OriginalDestinationConnectionID)
	require.Equal(t, protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}), p.InitialSourceConnectionID)
	require.Equal(t, &rcid, p.RetrySourceConnectionID)
	require.Equal(t, uint8(13), p.AckDelayExponent)
	require.Equal(t, 42*time.Millisecond, p.MaxAckDelay)
	require.Equal(t, params.ActiveConnectionIDLimit, p.ActiveConnectionIDLimit)
	require.Equal(t, params.MaxUDPPayloadSize, p.MaxUDPPayloadSize)
	require.Equal(t, params.MaxDatagramFrameSize, p.MaxDatagramFrameSize)
}

func TestMarshalAdditionalTransportParameters(t *testing.T) {
	origAdditionalTransportParametersClient := AdditionalTransportParametersClient
	t.Cleanup(func() { AdditionalTransportParametersClient = origAdditionalTransportParametersClient })
	AdditionalTransportParametersClient = map[uint64][]byte{1337: []byte("foobar")}

	result := quicvarint.Append([]byte{}, 1337)
	result = quicvarint.Append(result, 6)
	result = append(result, []byte("foobar")...)

	params := &TransportParameters{}
	require.True(t, bytes.Contains(params.Marshal(protocol.PerspectiveClient), result))
	require.False(t, bytes.Contains(params.Marshal(protocol.PerspectiveServer), result))
}

func TestMarshalWithoutRetrySourceConnectionID(t *testing.T) {
	data := (&TransportParameters{
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 2,
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.Nil(t, p.RetrySourceConnectionID)
}

func TestMarshalZeroLengthRetrySourceConnectionID(t *testing.T) {
	rcid := protocol.ParseConnectionID([]byte{})
	data := (&TransportParameters{
		RetrySourceConnectionID: &rcid,
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 2,
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.NotNil(t, p.RetrySourceConnectionID)
	require.Zero(t, p.RetrySourceConnectionID.Len())
}

func TestTransportParameterNoMaxAckDelayIfDefault(t *testing.T) {
	const num = 1000
	var defaultLen, dataLen int
	maxAckDelay := protocol.DefaultMaxAckDelay + time.Millisecond
	for i := 0; i < num; i++ {
		dataDefault := (&TransportParameters{
			MaxAckDelay:         protocol.DefaultMaxAckDelay,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		defaultLen += len(dataDefault)
		data := (&TransportParameters{
			MaxAckDelay:         maxAckDelay,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		dataLen += len(data)
	}
	entryLen := quicvarint.Len(uint64(ackDelayExponentParameterID)) +
		quicvarint.Len(uint64(quicvarint.Len(uint64(maxAckDelay.Milliseconds())))) +
		quicvarint.Len(uint64(maxAckDelay.Milliseconds()))
	require.InDelta(t, float32(defaultLen)/num+float32(entryLen), float32(dataLen)/num, 1)
}

func TestTransportParameterNoAckDelayExponentIfDefault(t *testing.T) {
	const num = 1000
	var defaultLen, dataLen int
	for i := 0; i < num; i++ {
		dataDefault := (&TransportParameters{
			AckDelayExponent:    protocol.DefaultAckDelayExponent,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		defaultLen += len(dataDefault)
		data := (&TransportParameters{
			AckDelayExponent:    protocol.DefaultAckDelayExponent + 1,
			StatelessResetToken: &protocol.StatelessResetToken{},
		}).Marshal(protocol.PerspectiveServer)
		dataLen += len(data)
	}
	entryLen := quicvarint.Len(uint64(ackDelayExponentParameterID)) +
		quicvarint.Len(uint64(quicvarint.Len(protocol.DefaultAckDelayExponent+1))) +
		quicvarint.Len(protocol.DefaultAckDelayExponent+1)
	require.InDelta(t, float32(defaultLen)/num+float32(entryLen), float32(dataLen)/num, 1)
}

func TestTransportParameterSetsDefaultValuesWhenNotSent(t *testing.T) {
	data := (&TransportParameters{
		AckDelayExponent:        protocol.DefaultAckDelayExponent,
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: protocol.DefaultActiveConnectionIDLimit,
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	require.EqualValues(t, protocol.DefaultAckDelayExponent, p.AckDelayExponent)
	require.EqualValues(t, protocol.DefaultActiveConnectionIDLimit, p.ActiveConnectionIDLimit)
}

func TestTransportParameterErrors(t *testing.T) {
	tests := []struct {
		name           string
		params         *TransportParameters
		perspective    protocol.Perspective
		data           []byte
		expectedErrMsg string
	}{
		{
			name: "invalid stateless reset token length",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, 15)
				return append(b, make([]byte, 15)...)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "wrong length for stateless_reset_token: 15 (expected 16)",
		},
		{
			name: "small max UDP payload size",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(maxUDPPayloadSizeParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(1199)))
				return quicvarint.Append(b, 1199)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for max_udp_payload_size: 1199 (minimum 1200)",
		},
		{
			name: "active connection ID limit too small",
			params: &TransportParameters{
				ActiveConnectionIDLimit: 1,
				StatelessResetToken:     &protocol.StatelessResetToken{},
			},
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for active_connection_id_limit: 1 (minimum 2)",
		},
		{
			name: "ack delay exponent too large",
			params: &TransportParameters{
				AckDelayExponent:    21,
				StatelessResetToken: &protocol.StatelessResetToken{},
			},
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for ack_delay_exponent: 21 (maximum 20)",
		},
		{
			name: "disable active migration has content",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(disableActiveMigrationParameterID))
				b = quicvarint.Append(b, 6)
				return append(b, []byte("foobar")...)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "wrong length for disable_active_migration: 6 (expected empty)",
		},
		{
			name: "server doesn't set original destination connection ID",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, 16)
				b = append(b, make([]byte, 16)...)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "missing original_destination_connection_id",
		},
		{
			name:           "initial source connection ID is missing",
			data:           []byte{},
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "missing initial_source_connection_id",
		},
		{
			name: "max ack delay is too large",
			params: &TransportParameters{
				MaxAckDelay:         1 << 14 * time.Millisecond,
				StatelessResetToken: &protocol.StatelessResetToken{},
			},
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "invalid value for max_ack_delay: 16384ms (maximum 16383ms)",
		},
		{
			name: "varint value has wrong length",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
				b = quicvarint.Append(b, 2)
				val := uint64(0xdeadbeef)
				b = quicvarint.Append(b, val)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: fmt.Sprintf("inconsistent transport parameter length for transport parameter %#x", initialMaxStreamDataBidiLocalParameterID),
		},
		{
			name: "initial max streams bidi is too large",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(initialMaxStreamsBidiParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
				b = quicvarint.Append(b, uint64(protocol.MaxStreamCount+1))
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "initial_max_streams_bidi too large: 1152921504606846977 (maximum 1152921504606846976)",
		},
		{
			name: "initial max streams uni is too large",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(initialMaxStreamsUniParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(protocol.MaxStreamCount+1))))
				b = quicvarint.Append(b, uint64(protocol.MaxStreamCount+1))
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "initial_max_streams_uni too large: 1152921504606846977 (maximum 1152921504606846976)",
		},
		{
			name: "not enough data to read",
			data: func() []byte {
				b := quicvarint.Append(nil, 0x42)
				b = quicvarint.Append(b, 7)
				return append(b, []byte("foobar")...)
			}(),
			perspective:    protocol.PerspectiveServer,
			expectedErrMsg: "remaining length (6) smaller than parameter length (7)",
		},
		{
			name: "client sent stateless reset token",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(16)))
				return append(b, make([]byte, 16)...)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "client sent a stateless_reset_token",
		},
		{
			name: "client sent original destination connection ID",
			data: func() []byte {
				b := quicvarint.Append(nil, uint64(originalDestinationConnectionIDParameterID))
				b = quicvarint.Append(b, 6)
				return append(b, []byte("foobar")...)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "client sent an original_destination_connection_id",
		},
		{
			name: "huge max ack delay value",
			data: func() []byte {
				val := uint64(math.MaxUint64) / 5
				b := quicvarint.Append(nil, uint64(maxAckDelayParameterID))
				b = quicvarint.Append(b, uint64(quicvarint.Len(val)))
				b = quicvarint.Append(b, val)
				return appendInitialSourceConnectionID(b)
			}(),
			perspective:    protocol.PerspectiveClient,
			expectedErrMsg: "invalid value for max_ack_delay: 3689348814741910323ms (maximum 16383ms)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.params != nil {
				data := tt.params.Marshal(tt.perspective)
				err = (&TransportParameters{}).Unmarshal(data, tt.perspective)
			} else {
				err = (&TransportParameters{}).Unmarshal(tt.data, tt.perspective)
			}
			require.Error(t, err)
			transportErr, ok := err.(*qerr.TransportError)
			require.True(t, ok)
			require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
			require.Equal(t, tt.expectedErrMsg, transportErr.ErrorMessage)
		})
	}
}

func TestTransportParameterUnknownParameters(t *testing.T) {
	// write a known parameter
	b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
	b = quicvarint.Append(b, 0x1337)
	// write an unknown parameter
	b = quicvarint.Append(b, 0x42)
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)
	// write a known parameter
	b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x42)))
	b = quicvarint.Append(b, 0x42)
	b = appendInitialSourceConnectionID(b)
	p := &TransportParameters{}
	err := p.Unmarshal(b, protocol.PerspectiveClient)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(0x1337), p.InitialMaxStreamDataBidiLocal)
	require.Equal(t, protocol.ByteCount(0x42), p.InitialMaxStreamDataBidiRemote)
}

func TestTransportParameterRejectsDuplicateParameters(t *testing.T) {
	// write first parameter
	b := quicvarint.Append(nil, uint64(initialMaxStreamDataBidiLocalParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
	b = quicvarint.Append(b, 0x1337)
	// write a second parameter
	b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiRemoteParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x42)))
	b = quicvarint.Append(b, 0x42)
	// write first parameter again
	b = quicvarint.Append(b, uint64(initialMaxStreamDataBidiLocalParameterID))
	b = quicvarint.Append(b, uint64(quicvarint.Len(0x1337)))
	b = quicvarint.Append(b, 0x1337)
	b = appendInitialSourceConnectionID(b)
	err := (&TransportParameters{}).Unmarshal(b, protocol.PerspectiveClient)
	require.Error(t, err)
	transportErr, ok := err.(*qerr.TransportError)
	require.True(t, ok)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, fmt.Sprintf("received duplicate transport parameter %#x", initialMaxStreamDataBidiLocalParameterID), transportErr.ErrorMessage)
}

func TestTransportParameterPreferredAddress(t *testing.T) {
	testCases := []struct {
		name    string
		hasIPv4 bool
		hasIPv6 bool
	}{
		{"IPv4 and IPv6", true, true},
		{"IPv4 only", true, false},
		{"IPv6 only", false, true},
		{"neither IPv4 nor IPv6", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testTransportParameterPreferredAddress(t, tc.hasIPv4, tc.hasIPv6)
		})
	}
}

func testTransportParameterPreferredAddress(t *testing.T, hasIPv4, hasIPv6 bool) {
	addr4 := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42)
	addr6 := netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13)
	pa := &PreferredAddress{
		ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	if hasIPv4 {
		pa.IPv4 = addr4
	}
	if hasIPv6 {
		pa.IPv6 = addr6
	}

	data := (&TransportParameters{
		PreferredAddress:        pa,
		StatelessResetToken:     &protocol.StatelessResetToken{},
		ActiveConnectionIDLimit: 2,
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	require.NoError(t, p.Unmarshal(data, protocol.PerspectiveServer))
	if hasIPv4 {
		require.True(t, p.PreferredAddress.IPv4.IsValid())
		require.Equal(t, addr4, p.PreferredAddress.IPv4)
	} else {
		require.False(t, p.PreferredAddress.IPv4.IsValid())
	}
	if hasIPv6 {
		require.True(t, p.PreferredAddress.IPv6.IsValid())
		require.Equal(t, addr6, p.PreferredAddress.IPv6)
	} else {
		require.False(t, p.PreferredAddress.IPv6.IsValid())
	}
	require.Equal(t, pa.ConnectionID, p.PreferredAddress.ConnectionID)
	require.Equal(t, pa.StatelessResetToken, p.PreferredAddress.StatelessResetToken)
}

func TestTransportParameterPreferredAddressFromClient(t *testing.T) {
	b := quicvarint.Append(nil, uint64(preferredAddressParameterID))
	b = quicvarint.Append(b, 6)
	b = append(b, []byte("foobar")...)
	p := &TransportParameters{}
	err := p.Unmarshal(b, protocol.PerspectiveClient)
	require.Error(t, err)
	require.IsType(t, &qerr.TransportError{}, err)
	transportErr := err.(*qerr.TransportError)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, "client sent a preferred_address", transportErr.ErrorMessage)
}

func TestTransportParameterPreferredAddressZeroLengthConnectionID(t *testing.T) {
	pa := &PreferredAddress{
		IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42),
		IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13),
		ConnectionID:        protocol.ParseConnectionID([]byte{}),
		StatelessResetToken: protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	data := (&TransportParameters{
		PreferredAddress:    pa,
		StatelessResetToken: &protocol.StatelessResetToken{},
	}).Marshal(protocol.PerspectiveServer)
	p := &TransportParameters{}
	err := p.Unmarshal(data, protocol.PerspectiveServer)
	require.Error(t, err)
	require.IsType(t, &qerr.TransportError{}, err)
	transportErr := err.(*qerr.TransportError)
	require.Equal(t, qerr.TransportParameterError, transportErr.ErrorCode)
	require.Equal(t, "invalid connection ID length: 0", transportErr.ErrorMessage)
}

func TestPreferredAddressErrorOnEOF(t *testing.T) {
	raw := []byte{
		127, 0, 0, 1, // IPv4
		0, 42, // IPv4 Port
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // IPv6
		13, 37, // IPv6 Port,
		4, // conn ID len
		0xde, 0xad, 0xbe, 0xef,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, // stateless reset token
	}
	for i := 1; i < len(raw); i++ {
		b := quicvarint.Append(nil, uint64(preferredAddressParameterID))
		b = append(b, raw[:i]...)
		p := &TransportParameters{}
		err := p.Unmarshal(b, protocol.PerspectiveServer)
		require.Error(t, err)
	}
}

func TestTransportParametersFromSessionTicket(t *testing.T) {
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataUni:        protocol.ByteCount(getRandomValue()),
		InitialMaxData:                 protocol.ByteCount(getRandomValue()),
		MaxBidiStreamNum:               protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		MaxUniStreamNum:                protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		ActiveConnectionIDLimit:        2 + getRandomValueUpTo(quicvarint.Max-2),
		MaxDatagramFrameSize:           protocol.ByteCount(getRandomValueUpTo(uint64(MaxDatagramSize))),
	}
	require.True(t, params.ValidFor0RTT(params))
	b := params.MarshalForSessionTicket(nil)
	var tp TransportParameters
	require.NoError(t, tp.UnmarshalFromSessionTicket(b))
	require.Equal(t, params.InitialMaxStreamDataBidiLocal, tp.InitialMaxStreamDataBidiLocal)
	require.Equal(t, params.InitialMaxStreamDataBidiRemote, tp.InitialMaxStreamDataBidiRemote)
	require.Equal(t, params.InitialMaxStreamDataUni, tp.InitialMaxStreamDataUni)
	require.Equal(t, params.InitialMaxData, tp.InitialMaxData)
	require.Equal(t, params.MaxBidiStreamNum, tp.MaxBidiStreamNum)
	require.Equal(t, params.MaxUniStreamNum, tp.MaxUniStreamNum)
	require.Equal(t, params.ActiveConnectionIDLimit, tp.ActiveConnectionIDLimit)
	require.Equal(t, params.MaxDatagramFrameSize, tp.MaxDatagramFrameSize)
}

func TestSessionTicketInvalidTransportParameters(t *testing.T) {
	var p TransportParameters
	require.Error(t, p.UnmarshalFromSessionTicket([]byte("foobar")))
}

func TestSessionTicketTransportParameterVersionMismatch(t *testing.T) {
	var p TransportParameters
	data := p.MarshalForSessionTicket(nil)
	b := quicvarint.Append(nil, transportParameterMarshalingVersion+1)
	b = append(b, data[quicvarint.Len(transportParameterMarshalingVersion):]...)
	err := p.UnmarshalFromSessionTicket(b)
	require.EqualError(t, err, fmt.Sprintf("unknown transport parameter marshaling version: %d", transportParameterMarshalingVersion+1))
}

func TestTransportParametersValidFor0RTT(t *testing.T) {
	saved := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  1,
		InitialMaxStreamDataBidiRemote: 2,
		InitialMaxStreamDataUni:        3,
		InitialMaxData:                 4,
		MaxBidiStreamNum:               5,
		MaxUniStreamNum:                6,
		ActiveConnectionIDLimit:        7,
		MaxDatagramFrameSize:           1000,
	}

	tests := []struct {
		name   string
		modify func(*TransportParameters)
		valid  bool
	}{
		{
			name:   "No Changes",
			modify: func(p *TransportParameters) {},
			valid:  true,
		},
		{
			name: "InitialMaxStreamDataBidiLocal reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal - 1
			},
			valid: false,
		},
		{
			name: "InitialMaxStreamDataBidiLocal increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal + 1
			},
			valid: true,
		},
		{
			name: "InitialMaxStreamDataBidiRemote reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote - 1
			},
			valid: false,
		},
		{
			name: "InitialMaxStreamDataBidiRemote increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote + 1
			},
			valid: true,
		},
		{
			name:   "InitialMaxStreamDataUni reduced",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni - 1 },
			valid:  false,
		},
		{
			name:   "InitialMaxStreamDataUni increased",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni + 1 },
			valid:  true,
		},
		{
			name:   "InitialMaxData reduced",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData - 1 },
			valid:  false,
		},
		{
			name:   "InitialMaxData increased",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData + 1 },
			valid:  true,
		},
		{
			name:   "MaxBidiStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum - 1 },
			valid:  false,
		},
		{
			name:   "MaxBidiStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum + 1 },
			valid:  true,
		},
		{
			name:   "MaxUniStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum - 1 },
			valid:  false,
		},
		{
			name:   "MaxUniStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum + 1 },
			valid:  true,
		},
		{
			name:   "ActiveConnectionIDLimit changed",
			modify: func(p *TransportParameters) { p.ActiveConnectionIDLimit = 0 },
			valid:  false,
		},
		{
			name:   "MaxDatagramFrameSize increased",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize + 1 },
			valid:  true,
		},
		{
			name:   "MaxDatagramFrameSize reduced",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize - 1 },
			valid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := *saved
			tt.modify(&p)
			require.Equal(t, tt.valid, p.ValidFor0RTT(saved))
		})
	}
}

func TestTransportParametersValidAfter0RTT(t *testing.T) {
	saved := &TransportParameters{
		InitialMaxStreamDataBidiLocal:  1,
		InitialMaxStreamDataBidiRemote: 2,
		InitialMaxStreamDataUni:        3,
		InitialMaxData:                 4,
		MaxBidiStreamNum:               5,
		MaxUniStreamNum:                6,
		ActiveConnectionIDLimit:        7,
		MaxDatagramFrameSize:           1000,
	}

	tests := []struct {
		name   string
		modify func(*TransportParameters)
		reject bool
	}{
		{
			name:   "no changes",
			modify: func(p *TransportParameters) {},
			reject: false,
		},
		{
			name: "InitialMaxStreamDataBidiLocal reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal - 1
			},
			reject: true,
		},
		{
			name: "InitialMaxStreamDataBidiLocal increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiLocal = saved.InitialMaxStreamDataBidiLocal + 1
			},
			reject: false,
		},
		{
			name: "InitialMaxStreamDataBidiRemote reduced",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote - 1
			},
			reject: true,
		},
		{
			name: "InitialMaxStreamDataBidiRemote increased",
			modify: func(p *TransportParameters) {
				p.InitialMaxStreamDataBidiRemote = saved.InitialMaxStreamDataBidiRemote + 1
			},
			reject: false,
		},
		{
			name:   "InitialMaxStreamDataUni reduced",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni - 1 },
			reject: true,
		},
		{
			name:   "InitialMaxStreamDataUni increased",
			modify: func(p *TransportParameters) { p.InitialMaxStreamDataUni = saved.InitialMaxStreamDataUni + 1 },
			reject: false,
		},
		{
			name:   "InitialMaxData reduced",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData - 1 },
			reject: true,
		},
		{
			name:   "InitialMaxData increased",
			modify: func(p *TransportParameters) { p.InitialMaxData = saved.InitialMaxData + 1 },
			reject: false,
		},
		{
			name:   "MaxBidiStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum - 1 },
			reject: true,
		},
		{
			name:   "MaxBidiStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxBidiStreamNum = saved.MaxBidiStreamNum + 1 },
			reject: false,
		},
		{
			name:   "MaxUniStreamNum reduced",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum - 1 },
			reject: true,
		},
		{
			name:   "MaxUniStreamNum increased",
			modify: func(p *TransportParameters) { p.MaxUniStreamNum = saved.MaxUniStreamNum + 1 },
			reject: false,
		},
		{
			name:   "ActiveConnectionIDLimit reduced",
			modify: func(p *TransportParameters) { p.ActiveConnectionIDLimit = saved.ActiveConnectionIDLimit - 1 },
			reject: true,
		},
		{
			name:   "ActiveConnectionIDLimit increased",
			modify: func(p *TransportParameters) { p.ActiveConnectionIDLimit = saved.ActiveConnectionIDLimit + 1 },
			reject: false,
		},
		{
			name:   "MaxDatagramFrameSize reduced",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize - 1 },
			reject: true,
		},
		{
			name:   "MaxDatagramFrameSize increased",
			modify: func(p *TransportParameters) { p.MaxDatagramFrameSize = saved.MaxDatagramFrameSize + 1 },
			reject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := *saved
			tt.modify(&p)
			if tt.reject {
				require.False(t, p.ValidForUpdate(saved))
			} else {
				require.True(t, p.ValidForUpdate(saved))
			}
		})
	}
}

func BenchmarkTransportParameters(b *testing.B) {
	b.Run("without preferred address", func(b *testing.B) { benchmarkTransportParameters(b, false) })
	b.Run("with preferred address", func(b *testing.B) { benchmarkTransportParameters(b, true) })
}

func benchmarkTransportParameters(b *testing.B, withPreferredAddress bool) {
	var token protocol.StatelessResetToken
	rand.Read(token[:])
	rcid := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xc0, 0xde})
	params := &TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(getRandomValue()),
		InitialMaxStreamDataUni:         protocol.ByteCount(getRandomValue()),
		InitialMaxData:                  protocol.ByteCount(getRandomValue()),
		MaxIdleTimeout:                  0xcafe * time.Second,
		MaxBidiStreamNum:                protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		MaxUniStreamNum:                 protocol.StreamNum(getRandomValueUpTo(uint64(protocol.MaxStreamCount))),
		DisableActiveMigration:          true,
		StatelessResetToken:             &token,
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{0xde, 0xca, 0xfb, 0xad}),
		RetrySourceConnectionID:         &rcid,
		AckDelayExponent:                13,
		MaxAckDelay:                     42 * time.Millisecond,
		ActiveConnectionIDLimit:         2 + getRandomValueUpTo(quicvarint.Max-2),
		MaxDatagramFrameSize:            protocol.ByteCount(getRandomValue()),
	}
	var token2 protocol.StatelessResetToken
	rand.Read(token2[:])
	if withPreferredAddress {
		var ip4 [4]byte
		var ip6 [16]byte
		rand.Read(ip4[:])
		rand.Read(ip6[:])
		params.PreferredAddress = &PreferredAddress{
			IPv4:                netip.AddrPortFrom(netip.AddrFrom4(ip4), 1234),
			IPv6:                netip.AddrPortFrom(netip.AddrFrom16(ip6), 4321),
			ConnectionID:        protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
			StatelessResetToken: token2,
		}
	}
	data := params.Marshal(protocol.PerspectiveServer)

	b.ResetTimer()
	b.ReportAllocs()
	var p TransportParameters
	for i := 0; i < b.N; i++ {
		if err := p.Unmarshal(data, protocol.PerspectiveServer); err != nil {
			b.Fatal(err)
		}
		// check a few fields
		if p.DisableActiveMigration != params.DisableActiveMigration ||
			p.InitialMaxStreamDataBidiLocal != params.InitialMaxStreamDataBidiLocal ||
			*p.StatelessResetToken != *params.StatelessResetToken ||
			p.AckDelayExponent != params.AckDelayExponent {
			b.Fatalf("params mismatch: %v vs %v", p, params)
		}
		if withPreferredAddress && *p.PreferredAddress != *params.PreferredAddress {
			b.Fatalf("preferred address mismatch: %v vs %v", p.PreferredAddress, params.PreferredAddress)
		}
	}
}
