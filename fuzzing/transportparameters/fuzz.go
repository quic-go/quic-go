package transportparameters

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

//go:generate go run ./cmd/corpus.go
func Fuzz(data []byte) int {
	if len(data) <= 1 {
		return 0
	}

	if data[0]%2 == 0 {
		return fuzzTransportParametersForSessionTicket(data[1:])
	}
	return fuzzTransportParameters(data[1:])
}

func fuzzTransportParameters(data []byte) int {
	perspective := protocol.PerspectiveServer
	if data[0]%2 == 1 {
		perspective = protocol.PerspectiveServer
	}
	data = data[1:]

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
	buf := &bytes.Buffer{}
	tp.MarshalForSessionTicket(buf)
	tp2 := &wire.TransportParameters{}
	if err := tp2.UnmarshalFromSessionTicket(bytes.NewReader(buf.Bytes())); err != nil {
		panic(err)
	}
	return 1
}
