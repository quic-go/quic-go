package integrationtests

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	_ "github.com/lucas-clemente/quic-clients" // download clients
	"github.com/lucas-clemente/quic-go/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var proxy *UDPProxy

func runDropTest(incomingPacketDropper, outgoingPacketDropper dropCallback, version protocol.VersionNumber) {
	proxyPort := 12345

	clientPath := fmt.Sprintf(
		"%s/src/github.com/lucas-clemente/quic-clients/client-%s-debug",
		os.Getenv("GOPATH"),
		runtime.GOOS,
	)

	iPort, _ := strconv.Atoi(port)
	var err error
	proxy, err = NewUDPProxy(proxyPort, "localhost", iPort, incomingPacketDropper, outgoingPacketDropper)
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
	Expect(bytes.Contains(session.Out.Contents(), data)).To(BeTrue())
}

var _ = Describe("Drop Proxy", func() {
	AfterEach(func() {
		proxy.Stop()
		time.Sleep(time.Millisecond)
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			Context("dropping every 4th packet after the crypto handshake", func() {
				dropper := func(p PacketNumber) bool {
					if p <= 5 { // don't interfere with the crypto handshake
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
