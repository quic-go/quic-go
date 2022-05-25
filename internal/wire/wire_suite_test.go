package wire

import (
	"bytes"
	"testing"

	"github.com/lucas-clemente/quic-go/quicvarint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestWire(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

func encodeVarInt(i uint64) []byte {
	b := &bytes.Buffer{}
	quicvarint.Write(b, i)
	return b.Bytes()
}
