package handshake

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

const sessionTicketRevision = 0

type sessionTicket struct {
	Parameters *TransportParameters
}

func (t *sessionTicket) Marshal() []byte {
	b := &bytes.Buffer{}
	utils.WriteVarInt(b, sessionTicketRevision)
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
	var tp TransportParameters
	if err := tp.UnmarshalFromSessionTicket(b[len(b)-r.Len():]); err != nil {
		return fmt.Errorf("unmarshaling transport parameters from session ticket failed: %s", err.Error())
	}
	t.Parameters = &tp
	return nil
}
