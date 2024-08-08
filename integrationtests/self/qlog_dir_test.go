package self_test

import (
	"context"
	"os"
	"path"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

var _ = Describe("qlog dir tests", Serial, func() {
	var originalQlogDirValue string
	var tempTestDirPath string

	BeforeEach(func() {
		originalQlogDirValue = os.Getenv("QLOGDIR")
		var err error
		tempTestDirPath, err = os.MkdirTemp("", "temp_test_dir")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		err := os.Setenv("QLOGDIR", originalQlogDirValue)
		Expect(err).ToNot(HaveOccurred())
		err = os.RemoveAll(tempTestDirPath)
		Expect(err).ToNot(HaveOccurred())
	})

	handshake := func() {
		serverStopped := make(chan struct{})
		server, err := quic.ListenAddr(
			"localhost:0",
			getTLSConfig(),
			&quic.Config{
				Tracer: qlog.DefaultConnectionTracer,
			},
		)
		Expect(err).ToNot(HaveOccurred())

		go func() {
			defer GinkgoRecover()
			defer close(serverStopped)
			for {
				if _, err := server.Accept(context.Background()); err != nil {
					return
				}
			}
		}()

		conn, err := quic.DialAddr(
			context.Background(),
			server.Addr().String(),
			getTLSClientConfig(),
			&quic.Config{
				Tracer: qlog.DefaultConnectionTracer,
			},
		)
		Expect(err).ToNot(HaveOccurred())
		conn.CloseWithError(0, "")
		server.Close()
		<-serverStopped
	}

	It("environment variable is set", func() {
		qlogDir := path.Join(tempTestDirPath, "qlogs")
		err := os.Setenv("QLOGDIR", qlogDir)
		Expect(err).ToNot(HaveOccurred())
		handshake()
		_, err = os.Stat(tempTestDirPath)
		qlogDirCreated := !os.IsNotExist(err)
		Expect(qlogDirCreated).To(BeTrue())
		childs, err := os.ReadDir(qlogDir)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(childs)).To(Equal(2))
		odcids := make([]string, 0)
		vantagePoints := make([]string, 0)
		qlogFileNameRegexp := regexp.MustCompile(`^([0-f]+)_(client|server).sqlog$`)
		for _, child := range childs {
			matches := qlogFileNameRegexp.FindStringSubmatch(child.Name())
			Expect(matches).To(HaveLen(3))
			odcids = append(odcids, matches[1])
			vantagePoints = append(vantagePoints, matches[2])
		}
		Expect(odcids[0]).To(Equal(odcids[1]))
		Expect(vantagePoints).To(ContainElements("client", "server"))
	})
})
