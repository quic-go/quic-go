package http3

import (
	"bytes"
	"io"

	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FrameReader", func() {
	It("parses unknown frame types", func() {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, 0xdeadbeef)
		quicvarint.Write(buf, 0x42)
		buf.Write(make([]byte, 0x42))
		quicvarint.Write(buf, uint64(FrameTypeData))
		quicvarint.Write(buf, 0x1234)
		fr := &FrameReader{R: buf}

		err := fr.Next()
		Expect(err).ToNot(HaveOccurred())
		Expect(fr.Type).To(Equal(FrameType(0xdeadbeef)))
		Expect(fr.N).To(Equal(int64(0x42)))

		err = fr.Next()
		Expect(err).ToNot(HaveOccurred())
		Expect(fr.Type).To(Equal(FrameTypeData))
		Expect(fr.N).To(Equal(int64(0x1234)))
	})

	It("can start with a partially read stream", func() {
		buf := &bytes.Buffer{}
		buf.Write(make([]byte, 0x100))
		quicvarint.Write(buf, uint64(FrameTypeData))
		quicvarint.Write(buf, 0x200)
		fr := &FrameReader{R: buf, Type: FrameTypeHeaders, N: 0x100}

		err := fr.Next()
		Expect(err).ToNot(HaveOccurred())
		Expect(fr.Type).To(Equal(FrameTypeHeaders))
		Expect(fr.N).To(Equal(int64(0x100)))

		err = fr.Next()
		Expect(err).ToNot(HaveOccurred())
		Expect(fr.Type).To(Equal(FrameTypeData))
		Expect(fr.N).To(Equal(int64(0x200)))
	})

	It("errors on EOF", func() {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, uint64(FrameTypeData))
		quicvarint.Write(buf, 0x100)
		_, _ = buf.Write(make([]byte, 0xff))
		fr := &FrameReader{R: buf}

		err := fr.Next()
		Expect(err).ToNot(HaveOccurred())
		Expect(fr.Type).To(Equal(FrameType(FrameTypeData)))
		Expect(fr.N).To(Equal(int64(0x100)))

		err = fr.Next()
		Expect(err).To(MatchError(io.EOF))
	})

	It("errors on EOF", func() {
		buf := &bytes.Buffer{}
		quicvarint.Write(buf, uint64(FrameTypeData))
		quicvarint.Write(buf, 0x100)
		_, _ = buf.Write(make([]byte, 0x100))
		fr := &FrameReader{R: buf}

		err := fr.Next()
		Expect(err).ToNot(HaveOccurred())
		Expect(fr.Type).To(Equal(FrameType(FrameTypeData)))
		Expect(fr.N).To(Equal(int64(0x100)))

		b := make([]byte, 0x200)
		n, err := fr.Read(b)
		Expect(err).ToNot(HaveOccurred())
		Expect(n).To(Equal(0x100))

		n, err = fr.Read(b)
		Expect(err).To(MatchError(io.EOF))
		Expect(n).To(Equal(0))

	})
})
