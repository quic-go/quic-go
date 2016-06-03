package h2quic_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"

	_ "github.com/lucas-clemente/quic-clients" // download clients

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = Describe("Integration tests", func() {
	const dataLen = 50 * 1024
	const host = "127.0.0.1"

	var (
		server     *h2quic.Server
		clientPath string
		data       []byte
		port       string
	)

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, "Hello, World!\n")
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(data)
		Expect(err).NotTo(HaveOccurred())
	})

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(w, r.Body)
		Expect(err).NotTo(HaveOccurred())
	})

	BeforeSuite(func() {
		data = make([]byte, dataLen)
		_, err := rand.Read(data)
		Expect(err).NotTo(HaveOccurred())

		clientPath = fmt.Sprintf(
			"%s/src/github.com/lucas-clemente/quic-clients/client-%s-debug",
			os.Getenv("GOPATH"),
			runtime.GOOS,
		)

		server = &h2quic.Server{
			Server: &http.Server{
				TLSConfig: testdata.GetTLSConfig(),
			},
		}

		addr, err := net.ResolveUDPAddr("udp", host+":0")
		Expect(err).NotTo(HaveOccurred())
		conn, err := net.ListenUDP("udp", addr)
		Expect(err).NotTo(HaveOccurred())
		port = strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)

		go func() {
			defer GinkgoRecover()
			server.Serve(conn)
		}()
	})

	AfterSuite(func() {
		err := server.Close()
		Expect(err).NotTo(HaveOccurred())
	})

	for i := range protocol.SupportedVersions {
		version := protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %d", version), func() {
			It("gets a simple file", func() {
				command := exec.Command(
					clientPath,
					"--quic-version="+strconv.Itoa(int(version)),
					"--host="+host,
					"--port="+port,
					"https://quic.clemente.io/hello",
				)
				session, err := Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				defer session.Kill()
				Eventually(session).Should(Exit(0))
				Expect(session.Out).To(Say("Response:\nheaders: HTTP/1.1 200\nstatus: 200\n\nbody: Hello, World!\n"))
			})

			It("posts and reads a body", func() {
				command := exec.Command(
					clientPath,
					"--quic-version="+strconv.Itoa(int(version)),
					"--host="+host,
					"--port="+port,
					"--body=foo",
					"https://quic.clemente.io/echo",
				)
				session, err := Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				defer session.Kill()
				Eventually(session).Should(Exit(0))
				Expect(session.Out).To(Say("Response:\nheaders: HTTP/1.1 200\nstatus: 200\n\nbody: foo\n"))
			})

			It("gets a large file", func() {
				command := exec.Command(
					clientPath,
					"--quic-version="+strconv.Itoa(int(version)),
					"--host="+host,
					"--port="+port,
					"https://quic.clemente.io/data",
				)
				session, err := Start(command, nil, GinkgoWriter)
				Expect(err).NotTo(HaveOccurred())
				defer session.Kill()
				Eventually(session, 2).Should(Exit(0))
				Expect(bytes.Contains(session.Out.Contents(), data)).To(BeTrue())
			})

			It("gets many large files in parallel", func() {
				wg := sync.WaitGroup{}
				for i := 0; i < 10; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer GinkgoRecover()
						command := exec.Command(
							clientPath,
							"--quic-version="+strconv.Itoa(int(version)),
							"--host="+host,
							"--port="+port,
							"https://quic.clemente.io/data",
						)
						session, err := Start(command, nil, GinkgoWriter)
						Expect(err).NotTo(HaveOccurred())
						defer session.Kill()
						Eventually(session, 3).Should(Exit(0))
						Expect(bytes.Contains(session.Out.Contents(), data)).To(BeTrue())
					}()
				}
				wg.Wait()
			})
		})
	}
})
