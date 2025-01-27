package qlog

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path"
	"runtime"
	"strconv"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/logging"
	"github.com/stretchr/testify/require"
)

func TestOwnerStringRepresentation(t *testing.T) {
	testCases := []struct {
		owner    owner
		expected string
	}{
		{ownerLocal, "local"},
		{ownerRemote, "remote"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, tc.owner.String())
	}
}

func TestCategoryStringRepresentation(t *testing.T) {
	testCases := []struct {
		category category
		expected string
	}{
		{categoryConnectivity, "connectivity"},
		{categoryTransport, "transport"},
		{categoryRecovery, "recovery"},
		{categorySecurity, "security"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, tc.category.String())
	}
}

func TestPacketTypeStringRepresentation(t *testing.T) {
	testCases := []struct {
		packetType logging.PacketType
		expected   string
	}{
		{logging.PacketTypeInitial, "initial"},
		{logging.PacketTypeHandshake, "handshake"},
		{logging.PacketType0RTT, "0RTT"},
		{logging.PacketType1RTT, "1RTT"},
		{logging.PacketTypeStatelessReset, "stateless_reset"},
		{logging.PacketTypeRetry, "retry"},
		{logging.PacketTypeVersionNegotiation, "version_negotiation"},
		{logging.PacketTypeNotDetermined, ""},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, packetType(tc.packetType).String())
	}
}

func TestPacketDropReasonStringRepresentation(t *testing.T) {
	testCases := []struct {
		reason   logging.PacketDropReason
		expected string
	}{
		{logging.PacketDropKeyUnavailable, "key_unavailable"},
		{logging.PacketDropUnknownConnectionID, "unknown_connection_id"},
		{logging.PacketDropHeaderParseError, "header_parse_error"},
		{logging.PacketDropPayloadDecryptError, "payload_decrypt_error"},
		{logging.PacketDropProtocolViolation, "protocol_violation"},
		{logging.PacketDropDOSPrevention, "dos_prevention"},
		{logging.PacketDropUnsupportedVersion, "unsupported_version"},
		{logging.PacketDropUnexpectedPacket, "unexpected_packet"},
		{logging.PacketDropUnexpectedSourceConnectionID, "unexpected_source_connection_id"},
		{logging.PacketDropUnexpectedVersion, "unexpected_version"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, packetDropReason(tc.reason).String())
	}
}

func TestTimerTypeStringRepresentation(t *testing.T) {
	testCases := []struct {
		timerType logging.TimerType
		expected  string
	}{
		{logging.TimerTypeACK, "ack"},
		{logging.TimerTypePTO, "pto"},
		{logging.TimerTypePathProbe, "path_probe"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, timerType(tc.timerType).String())
	}
}

func TestKeyTypeStringRepresentation(t *testing.T) {
	testCases := []struct {
		encLevel    protocol.EncryptionLevel
		perspective protocol.Perspective
		expected    string
	}{
		{protocol.EncryptionInitial, protocol.PerspectiveClient, "client_initial_secret"},
		{protocol.EncryptionInitial, protocol.PerspectiveServer, "server_initial_secret"},
		{protocol.EncryptionHandshake, protocol.PerspectiveClient, "client_handshake_secret"},
		{protocol.EncryptionHandshake, protocol.PerspectiveServer, "server_handshake_secret"},
		{protocol.Encryption0RTT, protocol.PerspectiveClient, "client_0rtt_secret"},
		{protocol.Encryption0RTT, protocol.PerspectiveServer, "server_0rtt_secret"},
		{protocol.Encryption1RTT, protocol.PerspectiveClient, "client_1rtt_secret"},
		{protocol.Encryption1RTT, protocol.PerspectiveServer, "server_1rtt_secret"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, encLevelToKeyType(tc.encLevel, tc.perspective).String())
	}
}

func TestKeyUpdateTriggerStringRepresentation(t *testing.T) {
	testCases := []struct {
		trigger  keyUpdateTrigger
		expected string
	}{
		{keyUpdateTLS, "tls"},
		{keyUpdateRemote, "remote_update"},
		{keyUpdateLocal, "local_update"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, tc.trigger.String())
	}
}

func TestPacketNumberSpaceFromEncryptionLevel(t *testing.T) {
	testCases := []struct {
		encLevel protocol.EncryptionLevel
		expected string
	}{
		{protocol.EncryptionInitial, "initial"},
		{protocol.EncryptionHandshake, "handshake"},
		{protocol.Encryption0RTT, "application_data"},
		{protocol.Encryption1RTT, "application_data"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, encLevelToPacketNumberSpace(tc.encLevel))
	}
}

func TestTransportErrorStringRepresentationForEveryErrorCode(t *testing.T) {
	_, thisfile, _, ok := runtime.Caller(0)
	require.True(t, ok, "Failed to get current frame")
	filename := path.Join(path.Dir(thisfile), "../internal/qerr/error_codes.go")
	fileAst, err := parser.ParseFile(gotoken.NewFileSet(), filename, nil, 0)
	require.NoError(t, err)
	constSpecs := fileAst.Decls[2].(*ast.GenDecl).Specs
	require.Greater(t, len(constSpecs), 4)
	for _, c := range constSpecs {
		valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
		val, err := strconv.ParseInt(valString, 0, 64)
		require.NoError(t, err)
		require.NotEmpty(t, transportError(val).String())
	}
}

func TestTransportErrorStringRepresentation(t *testing.T) {
	testCases := []struct {
		err      qerr.TransportErrorCode
		expected string
	}{
		{qerr.NoError, "no_error"},
		{qerr.InternalError, "internal_error"},
		{qerr.ConnectionRefused, "connection_refused"},
		{qerr.FlowControlError, "flow_control_error"},
		{qerr.StreamLimitError, "stream_limit_error"},
		{qerr.StreamStateError, "stream_state_error"},
		{qerr.FrameEncodingError, "frame_encoding_error"},
		{qerr.ConnectionIDLimitError, "connection_id_limit_error"},
		{qerr.ProtocolViolation, "protocol_violation"},
		{qerr.InvalidToken, "invalid_token"},
		{qerr.ApplicationErrorErrorCode, "application_error"},
		{qerr.CryptoBufferExceeded, "crypto_buffer_exceeded"},
		{qerr.NoViablePathError, "no_viable_path"},
		{1337, ""},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, transportError(tc.err).String())
	}
}

func TestCongestionStateUpdatesStringRepresentation(t *testing.T) {
	testCases := []struct {
		state    logging.CongestionState
		expected string
	}{
		{logging.CongestionStateSlowStart, "slow_start"},
		{logging.CongestionStateCongestionAvoidance, "congestion_avoidance"},
		{logging.CongestionStateApplicationLimited, "application_limited"},
		{logging.CongestionStateRecovery, "recovery"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, congestionState(tc.state).String())
	}
}

func TestECNBitsStringRepresentation(t *testing.T) {
	testCases := []struct {
		ecn      logging.ECN
		expected string
	}{
		{logging.ECT0, "ECT(0)"},
		{logging.ECT1, "ECT(1)"},
		{logging.ECNCE, "CE"},
		{logging.ECTNot, "Not-ECT"},
		{42, "unknown ECN"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, ecn(tc.ecn).String())
	}
}

func TestECNStateStringRepresentation(t *testing.T) {
	testCases := []struct {
		state    logging.ECNState
		expected string
	}{
		{logging.ECNStateTesting, "testing"},
		{logging.ECNStateUnknown, "unknown"},
		{logging.ECNStateFailed, "failed"},
		{logging.ECNStateCapable, "capable"},
		{42, "unknown ECN state"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, ecnState(tc.state).String())
	}
}

func TestECNStateTriggerStringRepresentation(t *testing.T) {
	testCases := []struct {
		trigger  logging.ECNStateTrigger
		expected string
	}{
		{logging.ECNTriggerNoTrigger, ""},
		{logging.ECNFailedNoECNCounts, "ACK doesn't contain ECN marks"},
		{logging.ECNFailedDecreasedECNCounts, "ACK decreases ECN counts"},
		{logging.ECNFailedLostAllTestingPackets, "all ECN testing packets declared lost"},
		{logging.ECNFailedMoreECNCountsThanSent, "ACK contains more ECN counts than ECN-marked packets sent"},
		{logging.ECNFailedTooFewECNCounts, "ACK contains fewer new ECN counts than acknowledged ECN-marked packets"},
		{logging.ECNFailedManglingDetected, "ECN mangling detected"},
		{42, "unknown ECN state trigger"},
	}

	for _, tc := range testCases {
		require.Equal(t, tc.expected, ecnStateTrigger(tc.trigger).String())
	}
}
