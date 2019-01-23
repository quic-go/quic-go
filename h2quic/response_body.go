package h2quic

import (
	"io"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type responseBody struct {
	eofRead utils.AtomicBool

	dataStream quic.Stream
}

var _ io.ReadCloser = &responseBody{}

func (rb *responseBody) Read(b []byte) (int, error) {
	n, err := rb.dataStream.Read(b)
	if err == io.EOF {
		rb.eofRead.Set(true)
	}
	return n, err
}

func (rb *responseBody) Close() error {
	if !rb.eofRead.Get() {
		rb.dataStream.CancelRead(0)
	}
	return nil
}
