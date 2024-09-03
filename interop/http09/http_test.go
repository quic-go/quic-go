package http09

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP 0.9 integration tests", func() {
	var (
		ln    *quic.EarlyListener
		saddr net.Addr
		done  chan struct{}
	)

	http.HandleFunc("/helloworld", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello World!"))
	})

	BeforeEach(func() {
		server := &Server{}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		Expect(err).ToNot(HaveOccurred())
		tr := &quic.Transport{Conn: conn}
		tlsConf := testdata.GetTLSConfig()
		tlsConf.NextProtos = []string{NextProto}
		ln, err = tr.ListenEarly(tlsConf, &quic.Config{})
		Expect(err).ToNot(HaveOccurred())
		done = make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			_ = server.ServeListener(ln)
		}()
		saddr = ln.Addr()
	})

	AfterEach(func() {
		Expect(ln.Close()).To(Succeed())
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
		data, err := io.ReadAll(rsp.Body)
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
		data, err := io.ReadAll(rsp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("done")))
	})
})
