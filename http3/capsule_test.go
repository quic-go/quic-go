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
		b := quicvarint.Append(nil, 1337)
		b = quicvarint.Append(b, 6)
		b = append(b, []byte("foobar")...)

		ct, r, err := ParseCapsule(bytes.NewReader(b))
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
		b := quicvarint.Append(nil, 1337)
		b = quicvarint.Append(b, 6)
		b = append(b, []byte("foobar")...)

		for i := range b {
			ct, r, err := ParseCapsule(bytes.NewReader(b[:i]))
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
