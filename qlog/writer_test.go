package qlog

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"

	"github.com/quic-go/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type limitedWriter struct {
	io.WriteCloser
	N       int
	written int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.N {
		return 0, errors.New("writer full")
	}
	n, err := w.WriteCloser.Write(p)
	w.written += n
	return n, err
}

var _ = Describe("Writing", func() {
	It("stops writing when encountering an error", func() {
		buf := &bytes.Buffer{}
		t := NewConnectionTracer(
			&limitedWriter{WriteCloser: nopWriteCloser(buf), N: 250},
			protocol.PerspectiveServer,
			protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef}),
		)
		for i := uint32(0); i < 1000; i++ {
			t.UpdatedPTOCount(i)
		}

		b := &bytes.Buffer{}
		log.SetOutput(b)
		defer log.SetOutput(os.Stdout)
		t.Close()
		Expect(b.String()).To(ContainSubstring("writer full"))
	})
})
