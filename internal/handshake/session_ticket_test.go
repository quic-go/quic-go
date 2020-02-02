package handshake

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session Ticket", func() {
	It("marshals and unmarshals a session ticket", func() {
		params := &TransportParameters{
			InitialMaxStreamDataBidiLocal:  1,
			InitialMaxStreamDataBidiRemote: 2,
		}
		var t sessionTicket
		Expect(t.Unmarshal((&sessionTicket{Parameters: params}).Marshal())).To(Succeed())
		Expect(t.Parameters.InitialMaxStreamDataBidiLocal).To(BeEquivalentTo(1))
		Expect(t.Parameters.InitialMaxStreamDataBidiRemote).To(BeEquivalentTo(2))
	})

	It("refuses to unmarshal if the ticket is too short for the revision", func() {
		Expect((&sessionTicket{}).Unmarshal([]byte{})).To(MatchError("failed to read session ticket revision"))
	})

	It("refuses to unmarshal if the revision doesn't match", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, 1337)
		Expect((&sessionTicket{}).Unmarshal(b.Bytes())).To(MatchError("unknown session ticket revision: 1337"))
	})

	It("refuses to unmarshal if unmarshaling the transport parameters fails", func() {
		b := &bytes.Buffer{}
		utils.WriteVarInt(b, sessionTicketRevision)
		b.Write([]byte("foobar"))
		err := (&sessionTicket{}).Unmarshal(b.Bytes())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshaling transport parameters from session ticket failed"))
	})
})
