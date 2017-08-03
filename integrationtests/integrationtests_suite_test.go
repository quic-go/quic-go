package integrationtests

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"runtime"

	"strconv"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	_ "github.com/lucas-clemente/quic-go/integrationtests/tools/testlog"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

const (
	dataLen     = 500 * 1024       // 500 KB
	dataLongLen = 50 * 1024 * 1024 // 50 MB
)

var (
	server     *h2quic.Server
	dataMan    dataManager
	port       string
	clientPath string
	serverPath string
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Tests Suite")
}

var _ = BeforeSuite(setupHTTPHandlers)

var _ = BeforeEach(func() {
	_, thisfile, _, ok := runtime.Caller(0)
	if !ok {
		Fail("Failed to get current path")
	}
	clientPath = filepath.Join(thisfile, fmt.Sprintf("../../../quic-clients/client-%s-debug", runtime.GOOS))
	serverPath = filepath.Join(thisfile, fmt.Sprintf("../../../quic-clients/server-%s-debug", runtime.GOOS))
})

var _ = JustBeforeEach(startQuicServer)

var _ = AfterEach(stopQuicServer)

func setupHTTPHandlers() {
	defer GinkgoRecover()

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		_, err := io.WriteString(w, "Hello, World!\n")
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		data := dataMan.GetData()
		Expect(data).ToNot(HaveLen(0))
		_, err := w.Write(data)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		body, err := ioutil.ReadAll(r.Body)
		Expect(err).NotTo(HaveOccurred())
		_, err = w.Write(body)
		Expect(err).NotTo(HaveOccurred())
	})

}

func startQuicServer() {
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

func stopQuicServer() {
	Expect(server.Close()).NotTo(HaveOccurred())
}
