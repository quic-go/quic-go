package integrationtests

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/testdata"
	"github.com/tebeka/selenium"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"

	"testing"
)

const (
	dataLen = 50 * 1024
)

var (
	server *h2quic.Server
	data   []byte
	port   string

	docker *gexec.Session
	wd     selenium.WebDriver
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Tests Suite")
}

var _ = BeforeSuite(func() {
	setupHTTPHandlers()
	setupQuicServer()
	setupSelenium()
})

var _ = AfterSuite(func() {
	err := server.Close()
	Expect(err).NotTo(HaveOccurred())

	stopSelenium()
})

func setupHTTPHandlers() {
	defer GinkgoRecover()
	data = make([]byte, dataLen)
	_, err := rand.Read(data)
	Expect(err).NotTo(HaveOccurred())

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, "Hello, World!\n")
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(data)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(w, r.Body)
		Expect(err).NotTo(HaveOccurred())
	})
}

func setupQuicServer() {
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

func setupSelenium() {
	var err error
	pullCmd := exec.Command("docker", "pull", "selenium/standalone-chrome:latest")
	pull, err := gexec.Start(pullCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	// Assuming a download at 10 Mbit/s
	Eventually(pull, 10*time.Minute).Should(gexec.Exit(0))

	dockerCmd := exec.Command(
		"docker",
		"run",
		"-i",
		"--rm",
		"-p=4444:4444",
		"selenium/standalone-chrome:latest",
	)
	docker, err = gexec.Start(dockerCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(docker.Out, 5).Should(gbytes.Say("Selenium Server is up and running"))

	caps := selenium.Capabilities{
		"browserName": "chrome",
		"chromeOptions": map[string]interface{}{
			"args": []string{
				"--enable-quic",
				"--no-proxy-server",
				"--origin-to-force-quic-on=quic.clemente.io:443",
				fmt.Sprintf(`--host-resolver-rules=MAP quic.clemente.io:443 %s:%s`, GetLocalIP(), port),
			},
		},
	}
	wd, err = selenium.NewRemote(caps, "http://localhost:4444/wd/hub")
	Expect(err).NotTo(HaveOccurred())
}

func stopSelenium() {
	docker.Interrupt().Wait(1)
}

func GetLocalIP() string {
	// First, try finding interface docker0
	i, err := net.InterfaceByName("docker0")
	if err == nil {
		var addrs []net.Addr
		addrs, err = i.Addrs()
		Expect(err).NotTo(HaveOccurred())
		return addrs[0].(*net.IPNet).IP.String()
	}

	addrs, err := net.InterfaceAddrs()
	Expect(err).NotTo(HaveOccurred())
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	panic("no addr")
}
