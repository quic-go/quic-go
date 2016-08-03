package integrationtests

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/protocol"
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
	server      *h2quic.Server
	data        []byte
	port        string
	downloadDir string

	docker *gexec.Session
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Tests Suite")
}

var _ = BeforeSuite(func() {
	setupHTTPHandlers()
	setupQuicServer()
	setupDownloadDir()
	setupSelenium()
})

var _ = AfterSuite(func() {
	err := server.Close()
	Expect(err).NotTo(HaveOccurred())

	stopSelenium()
	removeDownloadDir()
}, 5)

var _ = AfterEach(func() {
	clearDownloadDir()
})

func setupHTTPHandlers() {
	defer GinkgoRecover()
	data = make([]byte, dataLen)
	_, err := rand.Read(data)
	Expect(err).NotTo(HaveOccurred())

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		_, err := io.WriteString(w, "Hello, World!\n")
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		_, err := w.Write(data)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
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
	pullCmd := exec.Command("docker", "pull", "lclemente/standalone-chrome:latest")
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
		fmt.Sprintf("-v=%s/:/home/seluser/Downloads/", downloadDir),
		"lclemente/standalone-chrome:latest",
	)
	docker, err = gexec.Start(dockerCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(docker.Out, 5).Should(gbytes.Say("Selenium Server is up and running"))
}

func stopSelenium() {
	docker.Interrupt().Wait()
}

func getWebdriverForVersion(version protocol.VersionNumber) selenium.WebDriver {
	caps := selenium.Capabilities{
		"browserName": "chrome",
		"chromeOptions": map[string]interface{}{
			"args": []string{
				"--enable-quic",
				"--no-proxy-server",
				"--origin-to-force-quic-on=quic.clemente.io:443",
				fmt.Sprintf(`--host-resolver-rules=MAP quic.clemente.io:443 %s:%s`, GetLocalIP(), port),
				fmt.Sprintf(`--quic-version=QUIC_VERSION_%d`, version),
			},
		},
	}
	wd, err := selenium.NewRemote(caps, "http://localhost:4444/wd/hub")
	Expect(err).NotTo(HaveOccurred())
	return wd
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

// create a temporary directory for Chrome downloads
// Docker will mount the Chrome download directory here
func setupDownloadDir() {
	var err error
	downloadDir, err = ioutil.TempDir("/tmp", "quicgodownloads")
	Expect(err).ToNot(HaveOccurred())
}

// delete all files in the download directory
func clearDownloadDir() {
	d, err := os.Open(downloadDir)
	defer d.Close()
	Expect(err).ToNot(HaveOccurred())
	filenames, err := d.Readdirnames(-1)
	Expect(err).ToNot(HaveOccurred())
	for _, filename := range filenames {
		err := os.Remove(filepath.Join(downloadDir, filename))
		Expect(err).ToNot(HaveOccurred())
	}
}

// delete the download directory
// must be empty when calling this function
func removeDownloadDir() {
	err := os.Remove(downloadDir)
	Expect(err).ToNot(HaveOccurred())
}
