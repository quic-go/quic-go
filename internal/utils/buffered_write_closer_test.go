package utils

import (
	"bufio"
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

var _ = Describe("buffered io.WriteCloser", func() {
	It("flushes before closing", func() {
		buf := &bytes.Buffer{}

		w := bufio.NewWriter(buf)
		wc := NewBufferedWriteCloser(w, &nopCloser{})
		wc.Write([]byte("foobar"))
		Expect(buf.Len()).To(BeZero())
		Expect(wc.Close()).To(Succeed())
		Expect(buf.String()).To(Equal("foobar"))
	})
})
