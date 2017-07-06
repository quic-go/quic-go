package integrationtests

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"

	"strconv"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

const (
	dataLen     = 500 * 1024       // 500 KB
	dataLongLen = 50 * 1024 * 1024 // 50 MB
)

var (
	server             *h2quic.Server
	dataMan            dataManager
	port               string
	clientPath         string
	serverPath         string
	nFilesUploaded     int32
	testEndpointCalled bool
	doneCalled         bool

	logFileName string // the log file set in the ginkgo flags
	logFile     *os.File
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Tests Suite")
}

var _ = BeforeSuite(setupHTTPHandlers)

// read the logfile command line flag
// to set call ginkgo -- -logfile=log.txt
func init() {
	flag.StringVar(&logFileName, "logfile", "", "log file")
}

var _ = BeforeEach(func() {
	// set custom time format for logs
	utils.SetLogTimeFormat("15:04:05.000")
	_, thisfile, _, ok := runtime.Caller(0)
	if !ok {
		Fail("Failed to get current path")
	}
	clientPath = filepath.Join(thisfile, fmt.Sprintf("../../../quic-clients/client-%s-debug", runtime.GOOS))
	serverPath = filepath.Join(thisfile, fmt.Sprintf("../../../quic-clients/server-%s-debug", runtime.GOOS))

	if len(logFileName) > 0 {
		var err error
		logFile, err = os.Create("./log.txt")
		Expect(err).ToNot(HaveOccurred())
		log.SetOutput(logFile)
		utils.SetLogLevel(utils.LogLevelDebug)
	}
})

var _ = JustBeforeEach(startQuicServer)

var _ = AfterEach(func() {
	stopQuicServer()

	if len(logFileName) > 0 {
		_ = logFile.Close()
	}

	nFilesUploaded = 0
	doneCalled = false
	testEndpointCalled = false
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

	http.HandleFunc("/prdata", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		sl := r.URL.Query().Get("len")
		l, err := strconv.Atoi(sl)
		Expect(err).NotTo(HaveOccurred())
		data := generatePRData(l)
		_, err = w.Write(data)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		body, err := ioutil.ReadAll(r.Body)
		Expect(err).NotTo(HaveOccurred())
		_, err = w.Write(body)
		Expect(err).NotTo(HaveOccurred())
	})

	// Requires the len & num GET parameters, e.g. /uploadtest?len=100&num=1
	http.HandleFunc("/uploadtest", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		response := uploadHTML
		response = strings.Replace(response, "LENGTH", r.URL.Query().Get("len"), -1)
		response = strings.Replace(response, "NUM", r.URL.Query().Get("num"), -1)
		_, err := io.WriteString(w, response)
		Expect(err).NotTo(HaveOccurred())
		testEndpointCalled = true
	})

	// Requires the len & num GET parameters, e.g. /downloadtest?len=100&num=1
	http.HandleFunc("/downloadtest", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		response := downloadHTML
		response = strings.Replace(response, "LENGTH", r.URL.Query().Get("len"), -1)
		response = strings.Replace(response, "NUM", r.URL.Query().Get("num"), -1)
		_, err := io.WriteString(w, response)
		Expect(err).NotTo(HaveOccurred())
		testEndpointCalled = true
	})

	http.HandleFunc("/uploadhandler", func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()

		l, err := strconv.Atoi(r.URL.Query().Get("len"))
		Expect(err).NotTo(HaveOccurred())

		defer r.Body.Close()
		actual, err := ioutil.ReadAll(r.Body)
		Expect(err).NotTo(HaveOccurred())

		Expect(bytes.Equal(actual, generatePRData(l))).To(BeTrue())

		atomic.AddInt32(&nFilesUploaded, 1)
	})

	http.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		doneCalled = true
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

func waitForDone() {
	Eventually(func() bool { return doneCalled }, 60).Should(BeTrue())
}

func waitForNUploaded(expected int) func() {
	return func() {
		Eventually(func() int32 {
			return atomic.LoadInt32(&nFilesUploaded)
		}, 60).Should(BeEquivalentTo(expected))
	}
}

const commonJS = `
var buf = new ArrayBuffer(LENGTH);
var prng = new Uint8Array(buf);
var seed = 1;
for (var i = 0; i < LENGTH; i++) {
	// https://en.wikipedia.org/wiki/Lehmer_random_number_generator
	seed = seed * 48271 % 2147483647;
	prng[i] = seed;
}
`

const uploadHTML = `
<html>
<body>
<script>
	console.log("Running DL test...");

  ` + commonJS + `
	for (var i = 0; i < NUM; i++) {
		var req = new XMLHttpRequest();
		req.open("POST", "/uploadhandler?len=" + LENGTH, true);
		req.send(buf);
	}
</script>
</body>
</html>
`

const downloadHTML = `
<html>
<body>
<script>
	console.log("Running DL test...");
	` + commonJS + `

	function verify(data) {
		if (data.length !== LENGTH) return false;
		for (var i = 0; i < LENGTH; i++) {
			if (data[i] !== prng[i]) return false;
		}
		return true;
	}

	var nOK = 0;
	for (var i = 0; i < NUM; i++) {
		let req = new XMLHttpRequest();
		req.responseType = "arraybuffer";
		req.open("POST", "/prdata?len=" + LENGTH, true);
		req.onreadystatechange = function () {
			if (req.readyState === XMLHttpRequest.DONE && req.status === 200) {
				if (verify(new Uint8Array(req.response))) {
					nOK++;
					if (nOK === NUM) {
						console.log("Done :)");
						var reqDone = new XMLHttpRequest();
						reqDone.open("GET", "/done");
						reqDone.send();
					}
				}
			}
		};
		req.send();
	}
</script>
</body>
</html>
`

// Same as in the JS code, see
// https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}
