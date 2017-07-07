package integrationtests

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"

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

	var proxy *quicproxy.QuicProxy

	runDropTest := func(dropCallback quicproxy.DropCallback, version protocol.VersionNumber) {
		var err error
		proxy, err = quicproxy.NewQuicProxy("localhost:0", quicproxy.Opts{
			RemoteAddr: "localhost:" + port,
			DropPacket: dropCallback,
		})
		Expect(err).ToNot(HaveOccurred())

		command := exec.Command(
			clientPath,
			"--quic-version="+strconv.Itoa(int(version)),
			"--host=127.0.0.1",
			"--port="+strconv.Itoa(proxy.LocalPort()),
			"https://quic.clemente.io/data",
		)

		session, err := Start(command, nil, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		defer session.Kill()
		Eventually(session, 20).Should(Exit(0))
		Expect(bytes.Contains(session.Out.Contents(), dataMan.GetData())).To(BeTrue())
	}

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
	})

	Context("after the crypto handshake", func() {
		for i := range protocol.SupportedVersions {
			version := protocol.SupportedVersions[i]

			Context(fmt.Sprintf("with quic version %d", version), func() {
				dropTests("dropping every 4th packet", 4, 1, runDropTest, version)
				dropTests("dropping 10 packets every 100 packets", 100, 10, runDropTest, version)
			})
		}
	})
})

func dropTests(
	context string,
	interval protocol.PacketNumber,
	dropInARow protocol.PacketNumber,
	runDropTest func(dropCallback quicproxy.DropCallback, version protocol.VersionNumber),
	version protocol.VersionNumber) {
	Context(context, func() {
		dropper := func(p protocol.PacketNumber) bool {
			if p <= 10 { // don't interfere with the crypto handshake
				return false
			}
			return (p % interval) < dropInARow
		}

		It("gets a file when many outgoing packets are dropped", func() {
			runDropTest(func(d quicproxy.Direction, p protocol.PacketNumber) bool {
				return d == quicproxy.DirectionOutgoing && dropper(p)
			}, version)
		})

		It("gets a file when many incoming packets are dropped", func() {
			runDropTest(func(d quicproxy.Direction, p protocol.PacketNumber) bool {
				return d == quicproxy.DirectionIncoming && dropper(p)
			}, version)
		})
	})
}
