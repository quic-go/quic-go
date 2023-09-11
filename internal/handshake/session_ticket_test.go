package handshake

import (
	"time"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session Ticket", func() {
	It("marshals and unmarshals a 0-RTT session ticket", func() {
		ticket := &sessionTicket{
			Parameters: &wire.TransportParameters{
				InitialMaxStreamDataBidiLocal:  1,
				InitialMaxStreamDataBidiRemote: 2,
				ActiveConnectionIDLimit:        10,
				MaxDatagramFrameSize:           20,
			},
			RTT: 1337 * time.Microsecond,
		}
		var t sessionTicket
		Expect(t.Unmarshal(ticket.Marshal(), true)).To(Succeed())
		Expect(t.Parameters.InitialMaxStreamDataBidiLocal).To(BeEquivalentTo(1))
		Expect(t.Parameters.InitialMaxStreamDataBidiRemote).To(BeEquivalentTo(2))
		Expect(t.Parameters.ActiveConnectionIDLimit).To(BeEquivalentTo(10))
		Expect(t.Parameters.MaxDatagramFrameSize).To(BeEquivalentTo(20))
		Expect(t.RTT).To(Equal(1337 * time.Microsecond))
		// fails to unmarshal the ticket as a non-0-RTT ticket
		Expect(t.Unmarshal(ticket.Marshal(), false)).To(MatchError("the session ticket has more bytes than expected"))
	})

	It("marshals and unmarshals a non-0-RTT session ticket", func() {
		ticket := &sessionTicket{
			RTT: 1337 * time.Microsecond,
		}
		var t sessionTicket
		Expect(t.Unmarshal(ticket.Marshal(), false)).To(Succeed())
		Expect(t.Parameters).To(BeNil())
		Expect(t.RTT).To(Equal(1337 * time.Microsecond))
		// fails to unmarshal the ticket as a 0-RTT ticket
		Expect(t.Unmarshal(ticket.Marshal(), true)).To(MatchError(ContainSubstring("unmarshaling transport parameters from session ticket failed")))
	})

	It("refuses to unmarshal if the ticket is too short for the revision", func() {
		Expect((&sessionTicket{}).Unmarshal([]byte{}, true)).To(MatchError("failed to read session ticket revision"))
		Expect((&sessionTicket{}).Unmarshal([]byte{}, false)).To(MatchError("failed to read session ticket revision"))
	})

	It("refuses to unmarshal if the revision doesn't match", func() {
		b := quicvarint.Append(nil, 1337)
		Expect((&sessionTicket{}).Unmarshal(b, true)).To(MatchError("unknown session ticket revision: 1337"))
		Expect((&sessionTicket{}).Unmarshal(b, false)).To(MatchError("unknown session ticket revision: 1337"))
	})

	It("refuses to unmarshal if the RTT cannot be read", func() {
		b := quicvarint.Append(nil, sessionTicketRevision)
		Expect((&sessionTicket{}).Unmarshal(b, true)).To(MatchError("failed to read RTT"))
		Expect((&sessionTicket{}).Unmarshal(b, false)).To(MatchError("failed to read RTT"))
	})

	It("refuses to unmarshal a 0-RTT session ticket if unmarshaling the transport parameters fails", func() {
		b := quicvarint.Append(nil, sessionTicketRevision)
		b = append(b, []byte("foobar")...)
		err := (&sessionTicket{}).Unmarshal(b, true)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshaling transport parameters from session ticket failed"))
	})

	It("refuses to unmarshal if the non-0-RTT session ticket has more bytes than expected", func() {
		ticket := &sessionTicket{
			Parameters: &wire.TransportParameters{
				InitialMaxStreamDataBidiLocal:  1,
				InitialMaxStreamDataBidiRemote: 2,
				ActiveConnectionIDLimit:        10,
				MaxDatagramFrameSize:           20,
			},
			RTT: 1234 * time.Microsecond,
		}
		err := (&sessionTicket{}).Unmarshal(ticket.Marshal(), false)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("the session ticket has more bytes than expected"))
	})
})
