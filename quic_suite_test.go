package quic

import (
	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestQuicGo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "QUIC Suite")
}

const (
	versionCryptoStream1 = protocol.Version39
	versionCryptoStream0 = protocol.VersionTLS
)

var mockCtrl *gomock.Controller

var _ = BeforeSuite(func() {
	Expect(versionCryptoStream0.CryptoStreamID()).To(Equal(protocol.StreamID(0)))
	Expect(versionCryptoStream1.CryptoStreamID()).To(Equal(protocol.StreamID(1)))
})

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())
})

var _ = AfterEach(func() {
	mockCtrl.Finish()
})
