package self_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"sync"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("DPLPMTUD", func() {
	supportsDF := runtime.GOOS == "linux" || runtime.GOOS == "windows"
	name := "performs path MTU discovery"
	if !supportsDF {
		name = "doesn't perform MTU discovery"
	}

	It(name, func() {
		ln, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			getQuicConfig(nil),
		)
		Expect(err).ToNot(HaveOccurred())
		defer ln.Close()
		serverPort := ln.Addr().(*net.UDPAddr).Port

		maxSize := rand.Intn(150) + 1300
		var mx sync.Mutex
		var packetSizes []int
		proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
			RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
			DropPacket: func(dir quicproxy.Direction, b []byte) bool {
				if dir == quicproxy.DirectionIncoming {
					return false
				}
				mx.Lock()
				packetSizes = append(packetSizes, len(b))
				mx.Unlock()
				return len(b) > maxSize
			},
		})
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept(context.Background())
			Expect(err).ToNot(HaveOccurred())
			str, err := conn.OpenUniStream()
			Expect(err).ToNot(HaveOccurred())
			_, err = str.Write(PRDataLong)
			Expect(err).ToNot(HaveOccurred())
			Expect(str.Close()).To(Succeed())
		}()

		conn, err := quic.DialAddr(
			context.Background(),
			fmt.Sprintf("localhost:%d", proxy.LocalPort()),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		Expect(err).ToNot(HaveOccurred())
		str, err := conn.AcceptUniStream(context.Background())
		Expect(err).ToNot(HaveOccurred())
		data, err := io.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(PRDataLong))
		conn.CloseWithError(0, "")

		Expect(proxy.Close()).To(Succeed())

		if supportsDF {
			var tooLargeProbePackets []int
			var largestBelowMaxSize int
			var numMaxAllowedPacketSize int
			for _, s := range packetSizes {
				if s > maxSize {
					tooLargeProbePackets = append(tooLargeProbePackets, s)
					continue
				}
				if s == largestBelowMaxSize {
					numMaxAllowedPacketSize++
				}
				if s > largestBelowMaxSize {
					numMaxAllowedPacketSize = 1
					largestBelowMaxSize = s
				}
			}
			if len(tooLargeProbePackets) > 5 {
				fmt.Fprintf(GinkgoWriter, "max packet size: %d\nobserved probe packet sizes: %d", maxSize, tooLargeProbePackets)
				Fail("sent too many probe packet larger than the MTU")
			}
			// make sure we actually get close to the actual MTU
			Expect(largestBelowMaxSize).To(BeNumerically(">", maxSize-20))
			// make sure we stick with the value we found
			Expect(numMaxAllowedPacketSize).To(BeNumerically(">", 100))
		} else {
			for _, s := range packetSizes {
				Expect(s).To(BeNumerically("<", maxSize))
			}
		}
	})
})
