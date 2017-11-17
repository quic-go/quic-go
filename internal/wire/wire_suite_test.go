package wire

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wire Suite")
}

const (
	// a QUIC version that uses big endian encoding
	versionBigEndian = protocol.Version39
	// a QUIC version that uses the IETF frame types
	versionIETFFrames = protocol.VersionTLS
)

var _ = BeforeSuite(func() {
	Expect(utils.GetByteOrder(versionBigEndian)).To(Equal(utils.BigEndian))
	Expect(utils.GetByteOrder(versionIETFFrames)).To(Equal(utils.BigEndian))
	Expect(versionBigEndian.UsesIETFFrameFormat()).To(BeFalse())
	Expect(versionIETFFrames.UsesIETFFrameFormat()).To(BeTrue())
})
