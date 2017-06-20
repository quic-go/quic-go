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

var _ = Describe("non-zero RTT", func() {
	BeforeEach(func() {
		dataMan.GenerateData(dataLen)
	})

	var proxy *quicproxy.QuicProxy

	runRTTTest := func(rtt time.Duration, version protocol.VersionNumber) {
		var err error
		proxy, err = quicproxy.NewQuicProxy("localhost:", quicproxy.Opts{
			RemoteAddr: "localhost:" + port,
			DelayPacket: func(_ quicproxy.Direction, _ protocol.PacketNumber) time.Duration {
				return rtt / 2
			},
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
		err := proxy.Close()
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(time.Millisecond)
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			roundTrips := [...]int{10, 50, 100, 200}
			for _, rtt := range roundTrips {
				It(fmt.Sprintf("gets a 500kB file with %dms RTT", rtt), func() {
					dataMan.GenerateData(dataLen)
					runRTTTest(time.Duration(rtt)*time.Millisecond, version)
				})
			}
		})
	}
})
