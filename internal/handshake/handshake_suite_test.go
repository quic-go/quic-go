package handshake

import (
	"crypto"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"unsafe"

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

type cipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) cipher.AEAD
	Hash   crypto.Hash
}

//go:linkname cipherSuiteTLS13ByID github.com/marten-seemann/qtls.cipherSuiteTLS13ByID
func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13

func init() {
	val := cipherSuiteTLS13ByID(qtls.TLS_CHACHA20_POLY1305_SHA256)
	chacha := (*cipherSuiteTLS13)(unsafe.Pointer(val))
	for _, s := range cipherSuites {
		if s.ID == qtls.TLS_CHACHA20_POLY1305_SHA256 {
			if s.KeyLen != chacha.KeyLen || s.Hash != chacha.Hash {
				panic("invalid parameters for ChaCha20")
			}
			s.AEAD = chacha.AEAD
		}
	}
}
