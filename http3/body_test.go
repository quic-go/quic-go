package http3

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type closingBuffer struct {
	*bytes.Buffer

	closed bool
}

func (b *closingBuffer) Close() error { b.closed = true; return nil }

type bodyType uint8

const (
	bodyTypeRequest bodyType = iota
	bodyTypeResponse
)

var _ = Describe("Body", func() {
	var rb *body
	var buf *bytes.Buffer

	getDataFrame := func(data []byte) []byte {
		b := &bytes.Buffer{}
		(&dataFrame{Length: uint64(len(data))}).Write(b)
		b.Write(data)
		return b.Bytes()
	}

	BeforeEach(func() {
		buf = &bytes.Buffer{}
	})

	for _, bt := range []bodyType{bodyTypeRequest, bodyTypeResponse} {
		bodyType := bt

		BeforeEach(func() {
			cb := &closingBuffer{Buffer: buf}
			switch bodyType {
			case bodyTypeRequest:
				rb = newRequestBody(cb)
			case bodyTypeResponse:
				rb = newResponseBody(cb)
			}
		})

		It("reads DATA frames in a single run", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 6)
			n, err := rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b).To(Equal([]byte("foobar")))
		})

		It("reads DATA frames in multiple runs", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 3)
			n, err := rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b).To(Equal([]byte("foo")))
			n, err = rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b).To(Equal([]byte("bar")))
		})

		It("reads DATA frames into too large buffers", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 10)
			n, err := rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b[:n]).To(Equal([]byte("foobar")))
		})

		It("reads DATA frames into too large buffers, in multiple runs", func() {
			buf.Write(getDataFrame([]byte("foobar")))
			b := make([]byte, 4)
			n, err := rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(b).To(Equal([]byte("foob")))
			n, err = rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(2))
			Expect(b[:n]).To(Equal([]byte("ar")))
		})

		It("reads multiple DATA frames", func() {
			buf.Write(getDataFrame([]byte("foo")))
			buf.Write(getDataFrame([]byte("bar")))
			b := make([]byte, 6)
			n, err := rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b[:n]).To(Equal([]byte("foo")))
			n, err = rb.Read(b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(3))
			Expect(b[:n]).To(Equal([]byte("bar")))
		})

		It("skips HEADERS frames", func() {
			buf.Write(getDataFrame([]byte("foo")))
			(&headersFrame{Length: 10}).Write(buf)
			buf.Write(make([]byte, 10))
			buf.Write(getDataFrame([]byte("bar")))
			b := make([]byte, 6)
			n, err := io.ReadFull(rb, b)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(6))
			Expect(b).To(Equal([]byte("foobar")))
		})

		It("errors when it can't parse the frame", func() {
			buf.Write([]byte("invalid"))
			_, err := rb.Read([]byte{0})
			Expect(err).To(HaveOccurred())
		})

		It("errors on unexpected frames", func() {
			(&settingsFrame{}).Write(buf)
			_, err := rb.Read([]byte{0})
			Expect(err).To(MatchError("unexpected frame"))
		})
	}

	It("closes requests", func() {
		cb := &closingBuffer{Buffer: buf}
		rb := newRequestBody(cb)
		Expect(rb.Close()).To(Succeed())
		Expect(cb.closed).To(BeFalse())
	})

	It("closes responses", func() {
		cb := &closingBuffer{Buffer: buf}
		rb := newResponseBody(cb)
		Expect(rb.Close()).To(Succeed())
		Expect(cb.closed).To(BeTrue())
	})
})
