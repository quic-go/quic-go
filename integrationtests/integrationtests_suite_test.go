package integrationtests

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"

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
	dataLen     = 500 * 1024       // 500 KB
	dataLongLen = 50 * 1024 * 1024 // 50 MB
)

var (
	server     *h2quic.Server
	dataMan    dataManager
	port       string
	uploadDir  string
	clientPath string

	docker *gexec.Session
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
}, 10)

var _ = BeforeEach(func() {
	// create a new uploadDir for every test
	var err error
	uploadDir, err = ioutil.TempDir("", "quic-upload-dest")
	Expect(err).ToNot(HaveOccurred())
	err = os.MkdirAll(uploadDir, os.ModeDir|0777)
	Expect(err).ToNot(HaveOccurred())

	_, thisfile, _, ok := runtime.Caller(0)
	if !ok {
		Fail("Failed to get current path")
	}
	clientPath = filepath.Join(thisfile, fmt.Sprintf("../../../quic-clients/client-%s-debug", runtime.GOOS))
})

var _ = AfterEach(func() {
	// remove uploadDir
	if len(uploadDir) < 20 {
		panic("uploadDir too short")
	}
	os.RemoveAll(uploadDir)

	// remove downloaded file in docker container
	removeDownload("data")
})

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

	// requires the num GET parameter, e.g. /uploadform?num=2
	// will create num input fields for uploading files
	http.HandleFunc("/uploadform", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		num, err := strconv.Atoi(r.URL.Query().Get("num"))
		Expect(err).ToNot(HaveOccurred())
		response := "<html><body>\n<form id='form' action='https://quic.clemente.io/uploadhandler' method='post' enctype='multipart/form-data'>"
		for i := 0; i < num; i++ {
			response += "<input type='file' id='upload_" + strconv.Itoa(i) + "' name='uploadfile_" + strconv.Itoa(i) + "' />"
		}
		response += "</form><body></html>"
		_, err = io.WriteString(w, response)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/uploadhandler", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()

		err := r.ParseMultipartForm(100 * (1 << 20)) // max. 100 MB
		Expect(err).ToNot(HaveOccurred())

		count := 0
		for {
			var file multipart.File
			var handler *multipart.FileHeader
			file, handler, err = r.FormFile("uploadfile_" + strconv.Itoa(count))
			if err != nil {
				break
			}
			count++
			f, err2 := os.OpenFile(path.Join(uploadDir, handler.Filename), os.O_WRONLY|os.O_CREATE, 0666)
			Expect(err2).ToNot(HaveOccurred())
			io.Copy(f, file)
			f.Close()
			file.Close()
		}
		Expect(count).ToNot(BeZero()) // there have been at least one uploaded file in this request

		_, err = io.WriteString(w, "")
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
	pullCmd := exec.Command("docker", "pull", "lclemente/standalone-chrome:dev")
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
		"--name", "quic-test-selenium",
		"lclemente/standalone-chrome:dev",
	)
	docker, err = gexec.Start(dockerCmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(docker.Out, 10).Should(gbytes.Say("Selenium Server is up and running"))
}

func stopSelenium() {
	docker.Interrupt().Wait(10)
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

func removeDownload(filename string) {
	cmd := exec.Command("docker", "exec", "-i", "quic-test-selenium", "rm", "-f", "/home/seluser/Downloads/"+filename)
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, 5).Should(gexec.Exit(0))
}

// getDownloadSize gets the file size of a file in the /home/seluser/Downloads folder in the docker container
func getDownloadSize(filename string) int {
	var out bytes.Buffer
	cmd := exec.Command("docker", "exec", "-i", "quic-test-selenium", "stat", "--printf=%s", "/home/seluser/Downloads/"+filename)
	session, err := gexec.Start(cmd, &out, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, 5).Should(gexec.Exit())
	if session.ExitCode() != 0 {
		return 0
	}
	Expect(out.Bytes()).ToNot(BeEmpty())
	size, err := strconv.Atoi(string(out.Bytes()))
	Expect(err).NotTo(HaveOccurred())
	return size
}

// getFileSize gets the file size of a file on the local file system
func getFileSize(filename string) int {
	file, err := os.Open(filename)
	Expect(err).ToNot(HaveOccurred())
	fi, err := file.Stat()
	Expect(err).ToNot(HaveOccurred())
	return int(fi.Size())
}

// getDownloadMD5 gets the md5 sum file of a file in the /home/seluser/Downloads folder in the docker container
func getDownloadMD5(filename string) []byte {
	var out bytes.Buffer
	cmd := exec.Command("docker", "exec", "-i", "quic-test-selenium", "md5sum", "/home/seluser/Downloads/"+filename)
	session, err := gexec.Start(cmd, &out, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, 5).Should(gexec.Exit())
	if session.ExitCode() != 0 {
		return nil
	}
	Expect(out.Bytes()).ToNot(BeEmpty())
	res, err := hex.DecodeString(string(out.Bytes()[0:32]))
	Expect(err).NotTo(HaveOccurred())
	return res
}

// getFileMD5 gets the md5 sum of a file on the local file system
func getFileMD5(filepath string) []byte {
	var result []byte
	file, err := os.Open(filepath)
	Expect(err).ToNot(HaveOccurred())
	defer file.Close()

	hash := md5.New()
	_, err = io.Copy(hash, file)
	Expect(err).ToNot(HaveOccurred())
	return hash.Sum(result)
}

// copyFileToDocker copies a file from the local file system into the /home/seluser/ directory in the docker container
func copyFileToDocker(filepath string) {
	cmd := exec.Command("docker", "cp", filepath, "quic-test-selenium:/home/seluser/")
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session, 5).Should(gexec.Exit(0))
}
