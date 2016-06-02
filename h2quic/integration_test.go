package h2quic_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/testdata"

	_ "github.com/lucas-clemente/quic-clients" // download clients

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

const port = "6729"
const host = "127.0.0.1"
const addr = host + ":" + port

var _ = Describe("Integration tests", func() {
	var (
		server     *h2quic.Server
		clientPath string
	)

	BeforeSuite(func() {
		clientPath = fmt.Sprintf(
			"%s/src/github.com/lucas-clemente/quic-clients/client-%s-debug",
			os.Getenv("GOPATH"),
			runtime.GOOS,
		)
		http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "Hello, World!\n")
		})
	})

	BeforeEach(func() {
		server = &h2quic.Server{
			Server: &http.Server{
				Addr:      addr,
				TLSConfig: testdata.GetTLSConfig(),
			},
		}
		go func() {
			defer GinkgoRecover()
			server.ListenAndServe()
		}()
		time.Sleep(10 * time.Millisecond)
	})

	AfterEach(func() {
		err := server.Close()
		Expect(err).NotTo(HaveOccurred())
	})

	It("downloads a single file", func() {
		command := exec.Command(
			clientPath,
			"--quic-version=32",
			"--host="+host,
			"--port="+port,
			"https://quic.clemente.io/hello",
		)
		session, err := Start(command, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(session).Should(Exit(0))
		Expect(session.Out).To(Say("Hello, World!\n"))
	})
})
