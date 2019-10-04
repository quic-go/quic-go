package http09

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP 0.9 integration tests", func() {
	var (
		server *Server
		saddr  net.Addr
		done   chan struct{}
	)

	http.HandleFunc("/helloworld", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World!"))
	})

	BeforeEach(func() {
		server = &Server{
			Server: &http.Server{TLSConfig: testdata.GetTLSConfig()},
		}
		done = make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			_ = server.ListenAndServe()
		}()
		var ln quic.Listener
		Eventually(func() quic.Listener {
			server.mutex.Lock()
			defer server.mutex.Unlock()
			ln = server.listener
			return server.listener
		}).ShouldNot(BeNil())
		saddr = ln.Addr()
		saddr.(*net.UDPAddr).IP = net.IP{127, 0, 0, 1}
	})

	AfterEach(func() {
		Expect(server.Close()).To(Succeed())
		Eventually(done).Should(BeClosed())
	})

	It("performs request", func() {
		rt := &RoundTripper{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		defer rt.Close()
		req := httptest.NewRequest(
			http.MethodGet,
			fmt.Sprintf("https://%s/helloworld", saddr),
			nil,
		)
		rsp, err := rt.RoundTrip(req)
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(rsp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("Hello World!")))
	})

	It("allows setting of headers", func() {
		http.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("foo", "bar")
			w.WriteHeader(1337)
			_, _ = w.Write([]byte("done"))
		})

		rt := &RoundTripper{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		defer rt.Close()
		req := httptest.NewRequest(
			http.MethodGet,
			fmt.Sprintf("https://%s/headers", saddr),
			nil,
		)
		rsp, err := rt.RoundTrip(req)
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(rsp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("done")))
	})
})
