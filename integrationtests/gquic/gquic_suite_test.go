package gquic_test

import (
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"

	quicclients "github.com/lucas-clemente/quic-clients"
	_ "github.com/lucas-clemente/quic-go/integrationtests/tools/testlog"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	clientPath string
	serverPath string
	tempDir    string
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gQUIC Tests Suite")
}

var _ = BeforeSuite(func() {
	rand.Seed(GinkgoRandomSeed())
	var err error
	tempDir, err = ioutil.TempDir("", "gquic-toy")
	Expect(err).ToNot(HaveOccurred())
	// Go sets the permission of all files in the go mod directory to 0444.
	// We need to execute the quic client and server, so we need to copy them first.
	clientPath = copyToTmp(quicclients.Client())
	serverPath = copyToTmp(quicclients.Server())
})

func copyToTmp(source string) string {
	from, err := os.Open(source)
	Expect(err).ToNot(HaveOccurred())
	defer from.Close()
	dst := filepath.Join(tempDir, filepath.Base(source))
	to, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0555)
	Expect(err).ToNot(HaveOccurred())
	defer to.Close()
	_, err = io.Copy(to, from)
	Expect(err).ToNot(HaveOccurred())
	return dst
}

var _ = AfterSuite(func() {
	Expect(tempDir).ToNot(BeEmpty())
	Expect(os.RemoveAll(tempDir))
})

var _ = JustBeforeEach(func() {
	testserver.StartQuicServer(nil)
})

var _ = AfterEach(testserver.StopQuicServer)
