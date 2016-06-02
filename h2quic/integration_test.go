package h2quic_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/testdata"

	_ "github.com/lucas-clemente/quic-clients" // download clients

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

const port = "6729"
const host = "127.0.0.1"
const addr = host + ":" + port

const dataLen = 50 * 1024

var _ = Describe("Integration tests", func() {
	var (
		server     *h2quic.Server
		clientPath string
		data       []byte
	)

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})

	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	})

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
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
				Addr:      addr,
				TLSConfig: testdata.GetTLSConfig(),
			},
		}
		go func() {
			defer GinkgoRecover()
			server.ListenAndServe()
		}()
		time.Sleep(10 * time.Millisecond)
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
						Eventually(session, 3).Should(Exit(0))
						Expect(bytes.Contains(session.Out.Contents(), data)).To(BeTrue())
					}()
				}
				wg.Wait()
			})
		})
	}
})
