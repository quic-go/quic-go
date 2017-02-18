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

var _ = Describe("Drop Proxy", func() {
	BeforeEach(func() {
		dataMan.GenerateData(dataLen)
	})

	var dropproxy *proxy.UDPProxy

	runDropTest := func(incomingPacketDropper, outgoingPacketDropper proxy.DropCallback, version protocol.VersionNumber) {
		proxyPort := 12345

		iPort, _ := strconv.Atoi(port)
		var err error
		dropproxy, err = proxy.NewUDPProxy(proxyPort, "localhost", iPort, incomingPacketDropper, outgoingPacketDropper, 0, 0)
		Expect(err).ToNot(HaveOccurred())

		command := exec.Command(
			clientPath,
			"--quic-version="+strconv.Itoa(int(version)),
			"--host=127.0.0.1",
			"--port="+strconv.Itoa(proxyPort),
			"https://quic.clemente.io/data",
		)

		session, err := Start(command, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		defer session.Kill()
		Eventually(session, 20).Should(Exit(0))
		Expect(bytes.Contains(session.Out.Contents(), dataMan.GetData())).To(BeTrue())
	}

	AfterEach(func() {
		dropproxy.Stop()
		time.Sleep(time.Millisecond)
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			Context("dropping every 4th packet after the crypto handshake", func() {
				dropper := func(p protocol.PacketNumber) bool {
					if p <= 10 { // don't interfere with the crypto handshake
						return false
					}
					return p%4 == 0
				}

				It("gets a file when many outgoing packets are dropped", func() {
					runDropTest(nil, dropper, version)
				})

				It("gets a file when many incoming packets are dropped", func() {
					runDropTest(dropper, nil, version)
				})
			})
		})
	}
})
