package gquic_test

import (
	"bytes"
	"fmt"
	mrand "math/rand"
	"os/exec"
	"strconv"

	_ "github.com/lucas-clemente/quic-clients" // download clients
	"github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gexec"
)

var directions = []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing, quicproxy.DirectionBoth}

var _ = Describe("Drop tests", func() {
	var proxy *quicproxy.QuicProxy

	runDropTest := func(dropCallback quicproxy.DropCallback, version protocol.VersionNumber) {
		var err error
		proxy, err = quicproxy.NewQuicProxy("localhost:0", version, &quicproxy.Opts{
			RemoteAddr: "localhost:" + testserver.Port(),
			DropPacket: dropCallback,
		})
		Expect(err).ToNot(HaveOccurred())

		command := exec.Command(
			clientPath,
			"--quic-version="+strconv.Itoa(int(version)),
			"--host=127.0.0.1",
			"--port="+strconv.Itoa(proxy.LocalPort()),
			"https://quic.clemente.io/prdata",
		)

		session, err := Start(command, nil, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		defer session.Kill()
		Eventually(session, 20).Should(Exit(0))
		Expect(bytes.Contains(session.Out.Contents(), testserver.PRData)).To(BeTrue())
	}

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
	})

	Context("after the crypto handshake", func() {
		deterministicDropper := func(p, interval, dropInARow uint64) bool {
			if p <= 10 { // don't interfere with the crypto handshake
				return false
			}
			return (p % interval) < dropInARow
		}

		stochasticDropper := func(p protocol.PacketNumber, freq int) bool {
			if p <= 10 { // don't interfere with the crypto handshake
				return false
			}
			return mrand.Int63n(int64(freq)) == 0
		}

		for _, v := range protocol.SupportedVersions {
			version := v

			Context(fmt.Sprintf("with QUIC version %d", version), func() {
				for _, d := range directions {
					direction := d

					It(fmt.Sprintf("downloads a file when every 5th packet is dropped in %s direction", d), func() {
						runDropTest(func(d quicproxy.Direction, p uint64) bool {
							return d.Is(direction) && deterministicDropper(p, 5, 1)
						}, version)
					})

					It(fmt.Sprintf("downloads a file when 1/5th of all packet are dropped randomly in %s direction", d), func() {
						runDropTest(func(d quicproxy.Direction, p protocol.PacketNumber) bool {
							return d.Is(direction) && stochasticDropper(p, 5)
						}, version)
					})

					It(fmt.Sprintf("downloads a file when 10 packets every 100 packet are dropped in %s direction", d), func() {
						runDropTest(func(d quicproxy.Direction, p uint64) bool {
							return d.Is(direction) && deterministicDropper(p, 100, 10)
						}, version)
					})
				}
			})
		}
	})
})
