package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NEW_TOKEN frame", func() {
	Context("parsing", func() {
		It("accepts a sample frame", func() {
			token := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
			data := []byte{0x7}
			data = append(data, encodeVarInt(uint64(len(token)))...)
			data = append(data, token...)
			b := bytes.NewReader(data)
			f, err := parseNewTokenFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(f.Token)).To(Equal(token))
			Expect(b.Len()).To(BeZero())
		})

		It("rejects empty tokens", func() {
			data := []byte{0x7}
			data = append(data, encodeVarInt(uint64(0))...)
			b := bytes.NewReader(data)
			_, err := parseNewTokenFrame(b, protocol.VersionWhatever)
			Expect(err).To(MatchError("token must not be empty"))
		})

		It("errors on EOFs", func() {
			token := "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
			data := []byte{0x7}
			data = append(data, encodeVarInt(uint64(len(token)))...)
			data = append(data, token...)
			_, err := parseNewTokenFrame(bytes.NewReader(data), protocol.VersionWhatever)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseNewTokenFrame(bytes.NewReader(data[0:i]), protocol.VersionWhatever)
				Expect(err).To(HaveOccurred())
			}
		})
	})

	Context("writing", func() {
		It("writes a sample frame", func() {
			token := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
			f := &NewTokenFrame{Token: []byte(token)}
			b := &bytes.Buffer{}
			Expect(f.Write(b, protocol.VersionWhatever)).To(Succeed())
			expected := []byte{0x7}
			expected = append(expected, encodeVarInt(uint64(len(token)))...)
			expected = append(expected, token...)
			Expect(b.Bytes()).To(Equal(expected))
		})

		It("has the correct min length", func() {
			frame := &NewTokenFrame{Token: []byte("foobar")}
			Expect(frame.Length(protocol.VersionWhatever)).To(Equal(1 + utils.VarIntLen(6) + 6))
		})
	})
})
