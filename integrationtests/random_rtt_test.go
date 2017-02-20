package integrationtests

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	_ "github.com/lucas-clemente/quic-clients" // download clients
	"github.com/lucas-clemente/quic-go/integrationtests/proxy"
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("Random RTT", func() {
	BeforeEach(func() {
		dataMan.GenerateData(dataLen)
	})

	var rttProxy *proxy.UDPProxy

	runRTTTest := func(minRtt, maxRtt time.Duration, version protocol.VersionNumber) {
		proxyPort := 12345

		iPort, _ := strconv.Atoi(port)
		var err error
		rttProxy, err = proxy.NewUDPProxy(proxyPort, "localhost", iPort, nil, nil, minRtt, maxRtt)
		Expect(err).ToNot(HaveOccurred())

		command := exec.Command(
			clientPath,
			"--quic-version="+strconv.Itoa(int(version)),
			"--host=127.0.0.1",
			"--port="+strconv.Itoa(proxyPort),
			"https://quic.clemente.io/data",
		)

		session, err := Start(command, nil, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		defer session.Kill()
		Eventually(session, 4).Should(Exit(0))
		Expect(bytes.Contains(session.Out.Contents(), dataMan.GetData())).To(BeTrue())
	}

	AfterEach(func() {
		rttProxy.Stop()
		time.Sleep(time.Millisecond)
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			It("gets a file a random RTT between 10ms and 30ms", func() {
				runRTTTest(10*time.Millisecond, 30*time.Millisecond, version)
			})
		})
	}
})
