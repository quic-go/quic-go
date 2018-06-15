package self_test

import (
	"fmt"
	"io/ioutil"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testlog"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/testdata"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Multiplexing clients", func() {
	runServer := func() quic.Listener {
		ln, err := quic.ListenAddr("localhost:0", testdata.GetTLSConfig(), nil)
		Expect(err).ToNot(HaveOccurred())
		go func() {
			defer GinkgoRecover()
			for {
				sess, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer GinkgoRecover()
					str, err := sess.OpenStream()
					Expect(err).ToNot(HaveOccurred())
					defer str.Close()
					_, err = str.Write(testserver.PRDataLong)
					Expect(err).ToNot(HaveOccurred())
				}()
			}
		}()
		return ln
	}

	dial := func(conn net.PacketConn, addr net.Addr) {
		sess, err := quic.Dial(conn, addr, fmt.Sprintf("quic.clemente.io:%d", addr.(*net.UDPAddr).Port), nil, nil)
		Expect(err).ToNot(HaveOccurred())
		str, err := sess.AcceptStream()
		Expect(err).ToNot(HaveOccurred())
		data, err := ioutil.ReadAll(str)
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(testserver.PRDataLong))
	}

	It("multiplexes connections to the same server", func() {
		server := runServer()
		defer server.Close()

		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())

		done1 := make(chan struct{})
		done2 := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			dial(conn, server.Addr())
			close(done1)
		}()
		go func() {
			defer GinkgoRecover()
			dial(conn, server.Addr())
			close(done2)
		}()
		Consistently(done1).ShouldNot(BeClosed())
		Consistently(done2).ShouldNot(BeClosed())
		timeout := 15 * time.Second
		if testlog.Debug() {
			timeout = time.Minute
		}
		Eventually(done1, timeout).Should(BeClosed())
		Eventually(done2, timeout).Should(BeClosed())
	})

	It("multiplexes connections to different servers", func() {
		server1 := runServer()
		defer server1.Close()
		server2 := runServer()
		defer server2.Close()

		addr, err := net.ResolveUDPAddr("udp", "localhost:0")
		Expect(err).ToNot(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).ToNot(HaveOccurred())

		done1 := make(chan struct{})
		done2 := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			dial(conn, server1.Addr())
			close(done1)
		}()
		go func() {
			defer GinkgoRecover()
			dial(conn, server2.Addr())
			close(done2)
		}()
		Consistently(done1).ShouldNot(BeClosed())
		Consistently(done2).ShouldNot(BeClosed())
		timeout := 15 * time.Second
		if testlog.Debug() {
			timeout = time.Minute
		}
		Eventually(done1, timeout).Should(BeClosed())
		Eventually(done2, timeout).Should(BeClosed())
	})

})
