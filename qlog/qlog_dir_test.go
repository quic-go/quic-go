package qlog

import (
	"context"
	"os"
	"path"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
)

var _ = Describe("qlog dir tests", Serial, func() {
	var originalQlogDirValue string
	var tempTestDirPath string
	ctx := context.Background()
	perspective := logging.PerspectiveClient
	connID, _ := protocol.GenerateConnectionIDForInitial()

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

	It("environment variable is set", func() {
		qlogDir := path.Join(tempTestDirPath, "qlogs")
		err := os.Setenv("QLOGDIR", qlogDir)
		Expect(err).ToNot(HaveOccurred())
		tracer := DefaultConnectionTracer(ctx, perspective, connID)
		Expect(tracer).ToNot(BeNil())
		tracer.Close()
		_, err = os.Stat(qlogDir)
		qlogDirCreated := !os.IsNotExist(err)
		Expect(qlogDirCreated).To(BeTrue())
		childs, err := os.ReadDir(qlogDir)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(childs)).To(Equal(1))
	})

	It("environment variable is not set", func() {
		err := os.Setenv("QLOGDIR", "")
		Expect(err).ToNot(HaveOccurred())
		tracer := DefaultConnectionTracer(ctx, perspective, connID)
		Expect(tracer).To(BeNil())
	})
})
