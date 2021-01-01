package handshake

import (
	"bytes"
	"time"

	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session Ticket", func() {
	It("marshals and unmarshals a session ticket", func() {
		ticket := &sessionTicket{
			Parameters: &wire.TransportParameters{
				InitialMaxStreamDataBidiLocal:  1,
				InitialMaxStreamDataBidiRemote: 2,
			},
			RTT: 1337 * time.Microsecond,
		}
		var t sessionTicket
		Expect(t.Unmarshal(ticket.Marshal())).To(Succeed())
		Expect(t.Parameters.InitialMaxStreamDataBidiLocal).To(BeEquivalentTo(1))
		Expect(t.Parameters.InitialMaxStreamDataBidiRemote).To(BeEquivalentTo(2))
		Expect(t.RTT).To(Equal(1337 * time.Microsecond))
	})

	It("refuses to unmarshal if the ticket is too short for the revision", func() {
		Expect((&sessionTicket{}).Unmarshal([]byte{})).To(MatchError("failed to read session ticket revision"))
	})

	It("refuses to unmarshal if the revision doesn't match", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, 1337)
		Expect((&sessionTicket{}).Unmarshal(b.Bytes())).To(MatchError("unknown session ticket revision: 1337"))
	})

	It("refuses to unmarshal if the RTT cannot be read", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, sessionTicketRevision)
		Expect((&sessionTicket{}).Unmarshal(b.Bytes())).To(MatchError("failed to read RTT"))
	})

	It("refuses to unmarshal if unmarshaling the transport parameters fails", func() {
		b := &bytes.Buffer{}
		quicvarint.Write(b, sessionTicketRevision)
		b.Write([]byte("foobar"))
		err := (&sessionTicket{}).Unmarshal(b.Bytes())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshaling transport parameters from session ticket failed"))
	})
})
