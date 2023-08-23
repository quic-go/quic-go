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
		Expect(t.Unmarshal(true, ticket.Marshal())).To(Succeed())
		Expect(t.Parameters.InitialMaxStreamDataBidiLocal).To(BeEquivalentTo(1))
		Expect(t.Parameters.InitialMaxStreamDataBidiRemote).To(BeEquivalentTo(2))
		Expect(t.Parameters.ActiveConnectionIDLimit).To(BeEquivalentTo(10))
		Expect(t.Parameters.MaxDatagramFrameSize).To(BeEquivalentTo(20))
		Expect(t.RTT).To(Equal(1337 * time.Microsecond))
	})

	It("marshals and unmarshals a non-0-RTT session ticket", func() {
		ticket := &sessionTicket{
			RTT: 1337 * time.Microsecond,
		}
		var t sessionTicket
		Expect(t.Unmarshal(false, ticket.Marshal())).To(Succeed())
		Expect(t.Parameters).To(BeNil())
		Expect(t.RTT).To(Equal(1337 * time.Microsecond))
	})

	It("refuses to unmarshal if the ticket is too short for the revision", func() {
		Expect((&sessionTicket{}).Unmarshal(true, []byte{})).To(MatchError("failed to read session ticket revision"))
		Expect((&sessionTicket{}).Unmarshal(false, []byte{})).To(MatchError("failed to read session ticket revision"))
	})

	It("refuses to unmarshal if the revision doesn't match", func() {
		b := quicvarint.Append(nil, 1337)
		Expect((&sessionTicket{}).Unmarshal(true, b)).To(MatchError("unknown session ticket revision: 1337"))
		Expect((&sessionTicket{}).Unmarshal(false, b)).To(MatchError("unknown session ticket revision: 1337"))
	})

	It("refuses to unmarshal if the RTT cannot be read", func() {
		b := quicvarint.Append(nil, sessionTicketRevision)
		Expect((&sessionTicket{}).Unmarshal(true, b)).To(MatchError("failed to read RTT"))
		Expect((&sessionTicket{}).Unmarshal(false, b)).To(MatchError("failed to read RTT"))
	})

	It("refuses to unmarshal a 0-RTT session ticket if unmarshaling the transport parameters fails", func() {
		b := quicvarint.Append(nil, sessionTicketRevision)
		b = append(b, []byte("foobar")...)
		err := (&sessionTicket{}).Unmarshal(true, b)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshaling transport parameters from session ticket failed"))
	})
})
