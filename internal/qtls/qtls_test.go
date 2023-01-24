package qtls

import (
	"crypto/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("qtls wrapper", func() {
	It("gets cipher suites", func() {
		for _, id := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
			cs := CipherSuiteTLS13ByID(id)
			Expect(cs.ID).To(Equal(id))
		}
	})
})
