package transportparameters

import (
	"errors"
	"fmt"

	"github.com/Noooste/quic-go/fuzzing/internal/helper"
	"github.com/Noooste/quic-go/internal/protocol"
	"github.com/Noooste/quic-go/internal/wire"
)

// PrefixLen is the number of bytes used for configuration
const PrefixLen = 1

// Fuzz fuzzes the QUIC transport parameters.
//
//go:generate go run ./cmd/corpus.go
func Fuzz(data []byte) int {
	if len(data) <= PrefixLen {
		return 0
	}

	if helper.NthBit(data[0], 0) {
		return fuzzTransportParametersForSessionTicket(data[PrefixLen:])
	}
	return fuzzTransportParameters(data[PrefixLen:], helper.NthBit(data[0], 1))
}

func fuzzTransportParameters(data []byte, sentByServer bool) int {
	sentBy := protocol.PerspectiveClient
	if sentByServer {
		sentBy = protocol.PerspectiveServer
	}

	tp := &wire.TransportParameters{}
	if err := tp.Unmarshal(data, sentBy); err != nil {
		return 0
	}
	_ = tp.String()
	if err := validateTransportParameters(tp, sentBy); err != nil {
		panic(err)
	}

	tp2 := &wire.TransportParameters{}
	if err := tp2.Unmarshal(tp.Marshal(sentBy), sentBy); err != nil {
		fmt.Printf("%#v\n", tp)
		panic(err)
	}
	if err := validateTransportParameters(tp2, sentBy); err != nil {
		panic(err)
	}
	return 1
}

func fuzzTransportParametersForSessionTicket(data []byte) int {
	tp := &wire.TransportParameters{}
	if err := tp.UnmarshalFromSessionTicket(data); err != nil {
		return 0
	}
	b := tp.MarshalForSessionTicket(nil)
	tp2 := &wire.TransportParameters{}
	if err := tp2.UnmarshalFromSessionTicket(b); err != nil {
		panic(err)
	}
	return 1
}

func validateTransportParameters(tp *wire.TransportParameters, sentBy protocol.Perspective) error {
	if sentBy == protocol.PerspectiveClient && tp.StatelessResetToken != nil {
		return errors.New("client's transport parameters contained stateless reset token")
	}
	if tp.MaxIdleTimeout < 0 {
		return fmt.Errorf("negative max_idle_timeout: %s", tp.MaxIdleTimeout)
	}
	if tp.AckDelayExponent > 20 {
		return fmt.Errorf("invalid ack_delay_exponent: %d", tp.AckDelayExponent)
	}
	if tp.MaxUDPPayloadSize < 1200 {
		return fmt.Errorf("invalid max_udp_payload_size: %d", tp.MaxUDPPayloadSize)
	}
	if tp.ActiveConnectionIDLimit < 2 {
		return fmt.Errorf("invalid active_connection_id_limit: %d", tp.ActiveConnectionIDLimit)
	}
	if tp.OriginalDestinationConnectionID.Len() > 20 {
		return fmt.Errorf("invalid original_destination_connection_id length: %s", tp.InitialSourceConnectionID)
	}
	if tp.InitialSourceConnectionID.Len() > 20 {
		return fmt.Errorf("invalid initial_source_connection_id length: %s", tp.InitialSourceConnectionID)
	}
	if tp.RetrySourceConnectionID != nil && tp.RetrySourceConnectionID.Len() > 20 {
		return fmt.Errorf("invalid retry_source_connection_id length: %s", tp.RetrySourceConnectionID)
	}
	if tp.PreferredAddress != nil && tp.PreferredAddress.ConnectionID.Len() > 20 {
		return fmt.Errorf("invalid preferred_address connection ID length: %s", tp.PreferredAddress.ConnectionID)
	}
	return nil
}
