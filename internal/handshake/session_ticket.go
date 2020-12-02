package handshake

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const sessionTicketRevision = 2

type sessionTicket struct {
	Parameters *wire.TransportParameters
	RTT        time.Duration // to be encoded in mus
}

func (t *sessionTicket) Marshal() []byte {
	b := &bytes.Buffer{}
	utils.WriteVarInt(b, sessionTicketRevision)
	utils.WriteVarInt(b, uint64(t.RTT.Microseconds()))
	t.Parameters.MarshalForSessionTicket(b)
	return b.Bytes()
}

func (t *sessionTicket) Unmarshal(b []byte) error {
	r := bytes.NewReader(b)
	rev, err := utils.ReadVarInt(r)
	if err != nil {
		return errors.New("failed to read session ticket revision")
	}
	if rev != sessionTicketRevision {
		return fmt.Errorf("unknown session ticket revision: %d", rev)
	}
	rtt, err := utils.ReadVarInt(r)
	if err != nil {
		return errors.New("failed to read RTT")
	}
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(r); err != nil {
		return fmt.Errorf("unmarshaling transport parameters from session ticket failed: %s", err.Error())
	}
	t.Parameters = &tp
	t.RTT = time.Duration(rtt) * time.Microsecond
	return nil
}
