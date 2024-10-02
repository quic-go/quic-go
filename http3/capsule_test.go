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
		buf := make([]byte, 3)
		n, err := r.Read(buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(3))
		Expect(buf).To(Equal([]byte("foo")))
		data, err := io.ReadAll(r)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("bar")))
	})

	It("writes capsules", func() {
		var buf bytes.Buffer
		Expect(WriteCapsule(&buf, 1337, []byte("foobar"))).To(Succeed())

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
				if i == 0 {
					Expect(err).To(MatchError(io.EOF))
				} else {
					Expect(err).To(MatchError(io.ErrUnexpectedEOF))
				}
				continue
			}
			Expect(ct).To(BeEquivalentTo(1337))
			_, err = io.ReadAll(r)
			Expect(err).To(Equal(io.ErrUnexpectedEOF))
		}
	})
})
