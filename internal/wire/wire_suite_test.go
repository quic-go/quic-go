package wire

import (
	"bytes"

	"github.com/Psiphon-Labs/quic-go/internal/protocol"
	"github.com/Psiphon-Labs/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestWire(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

const (
	// a QUIC version that uses the IETF frame types
	versionIETFFrames = protocol.VersionTLS
)

func encodeVarInt(i uint64) []byte {
	b := &bytes.Buffer{}
	utils.WriteVarInt(b, i)
	return b.Bytes()
}
