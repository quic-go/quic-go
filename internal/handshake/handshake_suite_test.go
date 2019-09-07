package handshake

import (
	"crypto"
	"crypto/cipher"

	"github.com/alangpierce/go-forceexport"
	"github.com/golang/mock/gomock"
	"github.com/marten-seemann/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
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

var aeadChaCha20Poly1305 func(key, nonceMask []byte) cipher.AEAD

var cipherSuites = []*qtls.CipherSuiteTLS13{
	&qtls.CipherSuiteTLS13{
		ID:     qtls.TLS_AES_128_GCM_SHA256,
		KeyLen: 16,
		AEAD:   qtls.AEADAESGCMTLS13,
		Hash:   crypto.SHA256,
	},
	&qtls.CipherSuiteTLS13{
		ID:     qtls.TLS_AES_256_GCM_SHA384,
		KeyLen: 32,
		AEAD:   qtls.AEADAESGCMTLS13,
		Hash:   crypto.SHA384,
	},
	&qtls.CipherSuiteTLS13{
		ID:     qtls.TLS_CHACHA20_POLY1305_SHA256,
		KeyLen: 32,
		AEAD:   nil, // will be set by init
		Hash:   crypto.SHA256,
	},
}

func init() {
	if err := forceexport.GetFunc(&aeadChaCha20Poly1305, "github.com/marten-seemann/qtls.aeadChaCha20Poly1305"); err != nil {
		panic(err)
	}
	for _, s := range cipherSuites {
		if s.ID == qtls.TLS_CHACHA20_POLY1305_SHA256 {
			s.AEAD = aeadChaCha20Poly1305
		}
	}
}
