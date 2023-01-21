package http3

import (
	"bytes"
	"io"

	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Capsule", func() {
	It("parses Capsules", func() {
		var buf bytes.Buffer
		quicvarint.Write(&buf, 1337)
		quicvarint.Write(&buf, 6)
		buf.WriteString("foobar")

		ct, r, err := ParseCapsule(&buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(ct).To(BeEquivalentTo(1337))
		val, err := io.ReadAll(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(val)).To(Equal("foobar"))
	})

	It("writes capsules", func() {
		var buf bytes.Buffer
		WriteCapsule(&buf, 1337, []byte("foobar"))

		ct, r, err := ParseCapsule(&buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(ct).To(BeEquivalentTo(1337))
		val, err := io.ReadAll(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(val)).To(Equal("foobar"))
	})

	It("errors on EOF", func() {
		var buf bytes.Buffer
		quicvarint.Write(&buf, 1337)
		quicvarint.Write(&buf, 6)
		buf.WriteString("foobar")
		data := buf.Bytes()

		for i := range data {
			ct, r, err := ParseCapsule(bytes.NewReader(data[:i]))
			if err != nil {
				Expect(err).To(MatchError(io.ErrUnexpectedEOF))
				continue
			}
			Expect(ct).To(BeEquivalentTo(1337))
			_, err = io.ReadAll(r)
			Expect(err).To(Equal(io.ErrUnexpectedEOF))
		}
	})
})
