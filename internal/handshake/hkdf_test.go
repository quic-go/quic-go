package handshake

import (
	"crypto"
	"crypto/rand"
	mrand "math/rand"

	"github.com/lucas-clemente/quic-go/internal/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Initial AEAD using AES-GCM", func() {
	It("gets the same results as qtls", func() {
		for i := 0; i < 20; i++ {
			secret := make([]byte, 32)
			rand.Read(secret)
			context := make([]byte, mrand.Intn(100))
			rand.Read(context)
			labelB := make([]byte, mrand.Intn(100))
			rand.Read(labelB)
			label := string(labelB)
			length := mrand.Intn(100)

			expanded := hkdfExpandLabel(crypto.SHA256, secret, context, label, length)
			expandedQTLS := qtls.HkdfExpandLabel(crypto.SHA256, secret, context, label, length)
			Expect(expanded).To(Equal(expandedQTLS))
		}
	})
})
