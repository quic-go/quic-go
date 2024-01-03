package qlog

import (
	"context"
	"fmt"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/logging"
)

var _ = Describe("Tracing", func() {
	var tempTestDirPath string
	ctx := context.Background()
	perspective := logging.PerspectiveClient
	connID, _ := protocol.GenerateConnectionIDForInitial()

	BeforeEach(func() {
		var err error
		tempTestDirPath, err = os.MkdirTemp("", "temp_test_dir")
		fmt.Println(tempTestDirPath)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		QlogDir = ""
		err := os.RemoveAll(tempTestDirPath)
		Expect(err).ToNot(HaveOccurred())
	})

	It("qlog dir ist set", func() {
		QlogDir = tempTestDirPath
		tracer := DefaultTracer(ctx, perspective, connID)
		Expect(tracer).ToNot(BeNil())
		tracer.Close()
		_, err := os.Stat(tempTestDirPath)
		qlogDirExist := !os.IsNotExist(err)
		Expect(qlogDirExist).To(BeTrue())
		childs, err := os.ReadDir(tempTestDirPath)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(childs)).To(Equal(1))
	})

	It("qlog dir is not set", func() {
		QlogDir = ""
		tracer := DefaultTracer(ctx, perspective, connID)
		Expect(tracer).To(BeNil())
	})
})
