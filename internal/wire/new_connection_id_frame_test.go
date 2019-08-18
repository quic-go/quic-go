package wire

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NEW_CONNECTION_ID frame", func() {
	Context("when parsing", func() {
		It("accepts a sample frame", func() {
			data := []byte{0x18}
			data = append(data, encodeVarInt(0xdeadbeef)...)              // sequence number
			data = append(data, encodeVarInt(0xcafe)...)                  // retire prior to
			data = append(data, 10)                                       // connection ID length
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // connection ID
			data = append(data, []byte("deadbeefdecafbad")...)            // stateless reset token
			b := bytes.NewReader(data)
			frame, err := parseNewConnectionIDFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.SequenceNumber).To(Equal(uint64(0xdeadbeef)))
			Expect(frame.RetirePriorTo).To(Equal(uint64(0xcafe)))
			Expect(frame.ConnectionID).To(Equal(protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}))
			Expect(string(frame.StatelessResetToken[:])).To(Equal("deadbeefdecafbad"))
		})

		It("errors when the Retire Prior To value is larger than the Sequence Number", func() {
			data := []byte{0x18}
			data = append(data, encodeVarInt(1000)...) // sequence number
			data = append(data, encodeVarInt(1001)...) // retire prior to
			data = append(data, 3)
			data = append(data, []byte{1, 2, 3}...)
			data = append(data, []byte("deadbeefdecafbad")...) // stateless reset token
			b := bytes.NewReader(data)
			_, err := parseNewConnectionIDFrame(b, versionIETFFrames)
			Expect(err).To(MatchError("Retire Prior To value (1001) larger than Sequence Number (1000)"))
		})

		It("errors when the connection ID has an invalid length", func() {
			data := []byte{0x18}
			data = append(data, encodeVarInt(0xdeadbeef)...)                                                          // sequence number
			data = append(data, encodeVarInt(0xcafe)...)                                                              // retire prior to
			data = append(data, 21)                                                                                   // connection ID length
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}...) // connection ID
			data = append(data, []byte("deadbeefdecafbad")...)                                                        // stateless reset token
			b := bytes.NewReader(data)
			_, err := parseNewConnectionIDFrame(b, versionIETFFrames)
			Expect(err).To(MatchError("invalid connection ID length: 21"))
		})

		It("errors on EOFs", func() {
			data := []byte{0x18}
			data = append(data, encodeVarInt(0xdeadbeef)...)              // sequence number
			data = append(data, encodeVarInt(0xcafe1234)...)              // retire prior to
			data = append(data, 10)                                       // connection ID length
			data = append(data, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}...) // connection ID
			data = append(data, []byte("deadbeefdecafbad")...)            // stateless reset token
			_, err := parseNewConnectionIDFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseNewConnectionIDFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			token := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			frame := &NewConnectionIDFrame{
				SequenceNumber:      0x1337,
				RetirePriorTo:       0x42,
				ConnectionID:        protocol.ConnectionID{1, 2, 3, 4, 5, 6},
				StatelessResetToken: token,
			}
			b := &bytes.Buffer{}
			Expect(frame.Write(b, versionIETFFrames)).To(Succeed())
			expected := []byte{0x18}
			expected = append(expected, encodeVarInt(0x1337)...)
			expected = append(expected, encodeVarInt(0x42)...)
			expected = append(expected, 6)
			expected = append(expected, []byte{1, 2, 3, 4, 5, 6}...)
			expected = append(expected, token[:]...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("has the correct length", func() {
			token := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			frame := &NewConnectionIDFrame{
				SequenceNumber:      0xdecafbad,
				RetirePriorTo:       0xdeadbeefcafe,
				ConnectionID:        protocol.ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
				StatelessResetToken: token,
			}
			b := &bytes.Buffer{}
			Expect(frame.Write(b, versionIETFFrames)).To(Succeed())
			Expect(frame.Length(versionIETFFrames)).To(BeEquivalentTo(b.Len()))
		})
	})
})
