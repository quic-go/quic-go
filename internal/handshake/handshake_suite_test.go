package handshake

import (
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/internal/qtls"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHandshake(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Handshake Suite")
}

var mockCtrl *gomock.Controller

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())
})

var _ = AfterEach(func() {
	mockCtrl.Finish()
})

func splitHexString(s string) (slice []byte) {
	for _, ss := range strings.Split(s, " ") {
		if ss[0:2] == "0x" {
			ss = ss[2:]
		}
		d, err := hex.DecodeString(ss)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		slice = append(slice, d...)
	}
	return
}

var cipherSuites = []*qtls.CipherSuiteTLS13{
	qtls.CipherSuiteTLS13ByID(tls.TLS_AES_128_GCM_SHA256),
	qtls.CipherSuiteTLS13ByID(tls.TLS_AES_256_GCM_SHA384),
	qtls.CipherSuiteTLS13ByID(tls.TLS_CHACHA20_POLY1305_SHA256),
}
