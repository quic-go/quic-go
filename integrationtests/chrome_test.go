package integrationtests

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

const (
	nChromeRetries = 8
)

func getChromePath() string {
	if runtime.GOOS == "darwin" {
		return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	return "google-chrome"
}

func chromeTest(version protocol.VersionNumber, url string, blockUntilDone func()) {
	// Chrome sometimes starts but doesn't send any HTTP requests for no apparent reason.
	// Retry starting it a couple of times.
	for i := 0; i < nChromeRetries; i++ {
		if chromeTestImpl(version, url, blockUntilDone) {
			return
		}
	}
	Fail("Chrome didn't hit the testing endpoints")
}

func chromeTestImpl(version protocol.VersionNumber, url string, blockUntilDone func()) bool {
	userDataDir, err := ioutil.TempDir("", "quic-go-test-chrome-dir")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(userDataDir)
	path := getChromePath()
	args := []string{
		"--disable-gpu",
		"--no-first-run=true",
		"--no-default-browser-check=true",
		"--user-data-dir=" + userDataDir,
		"--enable-quic=true",
		"--no-proxy-server=true",
		"--origin-to-force-quic-on=quic.clemente.io:443",
		fmt.Sprintf(`--host-resolver-rules=MAP quic.clemente.io:443 localhost:%s`, port),
		fmt.Sprintf("--quic-version=QUIC_VERSION_%d", version),
		url,
	}
	utils.Infof("Running chrome: %s '%s'", getChromePath(), strings.Join(args, "' '"))
	command := exec.Command(path, args...)
	session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	defer session.Kill()
	const pollInterval = 100 * time.Millisecond
	const pollDuration = 10 * time.Second
	for i := 0; i < int(pollDuration/pollInterval); i++ {
		time.Sleep(pollInterval)
		if testEndpointCalled {
			break
		}
	}
	if !testEndpointCalled {
		return false
	}
	blockUntilDone()
	return true
}

var _ = Describe("Chrome tests", func() {
	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			supportedVersionsBefore := protocol.SupportedVersions

			BeforeEach(func() {
				protocol.SupportedVersions = []protocol.VersionNumber{version}
			})

			AfterEach(func() {
				protocol.SupportedVersions = supportedVersionsBefore
			})

			It("downloads a small file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/downloadtest?num=1&len=%d", dataLen),
					waitForDone,
				)
			})

			It("downloads a large file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/downloadtest?num=1&len=%d", dataLongLen),
					waitForDone,
				)
			})

			It("loads a large number of files", func() {
				chromeTest(
					version,
					"https://quic.clemente.io/downloadtest?num=4&len=100",
					waitForDone,
				)
			})

			It("uploads a small file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/uploadtest?num=1&len=%d", dataLen),
					waitForNUploaded(1),
				)
			})

			It("uploads a large file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/uploadtest?num=1&len=%d", dataLongLen),
					waitForNUploaded(1),
				)
			})

			It("uploads many small files", func() {
				num := protocol.MaxStreamsPerConnection + 20
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/uploadtest?num=%d&len=%d", num, dataLen),
					waitForNUploaded(num),
				)
			})
		})
	}
})
