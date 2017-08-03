package testserver

import (
	"net"
	"net/http"
	"strconv"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	server *h2quic.Server
	port   string
)

func init() {
	http.HandleFunc("/prdata", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		sl := r.URL.Query().Get("len")
		l, err := strconv.Atoi(sl)
		Expect(err).NotTo(HaveOccurred())
		data := GeneratePRData(l)
		_, err = w.Write(data)
		Expect(err).NotTo(HaveOccurred())
	})
}

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func GeneratePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

func StartQuicServer() {
	server = &h2quic.Server{
		Server: &http.Server{
			TLSConfig: testdata.GetTLSConfig(),
		},
	}

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	Expect(err).NotTo(HaveOccurred())
	conn, err := net.ListenUDP("udp", addr)
	Expect(err).NotTo(HaveOccurred())
	port = strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)

	go func() {
		defer GinkgoRecover()
		server.Serve(conn)
	}()
}

func StopQuicServer() {
	Expect(server.Close()).NotTo(HaveOccurred())
}

func Port() string {
	return port
}
