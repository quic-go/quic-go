package transportparameters

import (
	"bytes"
	"fmt"

	"github.com/quic-go/quic-go/fuzzing/internal/helper"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
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

func fuzzTransportParameters(data []byte, isServer bool) int {
	perspective := protocol.PerspectiveClient
	if isServer {
		perspective = protocol.PerspectiveServer
	}

	tp := &wire.TransportParameters{}
	if err := tp.Unmarshal(data, perspective); err != nil {
		return 0
	}
	_ = tp.String()

	tp2 := &wire.TransportParameters{}
	if err := tp2.Unmarshal(tp.Marshal(perspective), perspective); err != nil {
		fmt.Printf("%#v\n", tp)
		panic(err)
	}
	return 1
}

func fuzzTransportParametersForSessionTicket(data []byte) int {
	tp := &wire.TransportParameters{}
	if err := tp.UnmarshalFromSessionTicket(bytes.NewReader(data)); err != nil {
		return 0
	}
	b := tp.MarshalForSessionTicket(nil)
	tp2 := &wire.TransportParameters{}
	if err := tp2.UnmarshalFromSessionTicket(bytes.NewReader(b)); err != nil {
		panic(err)
	}
	return 1
}
