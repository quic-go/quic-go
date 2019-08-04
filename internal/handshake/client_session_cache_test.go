package handshake

import (
	"crypto/tls"

	"github.com/marten-seemann/qtls"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ClientSessionCache", func() {
	var (
		csc      *clientSessionCache
		get, set chan []byte
	)

	BeforeEach(func() {
		get = make(chan []byte, 100)
		set = make(chan []byte, 100)
		csc = newClientSessionCache(
			tls.NewLRUClientSessionCache(100),
			func() []byte { return <-get },
			func(b []byte) { set <- b },
		)
	})

	It("puts and gets", func() {
		get <- []byte("foobar")
		csc.Put("localhost", &qtls.ClientSessionState{})
		Expect(set).To(BeEmpty())

		state, ok := csc.Get("localhost")
		Expect(ok).To(BeTrue())
		Expect(state).ToNot(BeNil())
		Expect(set).To(Receive(Equal([]byte("foobar"))))
	})
})
