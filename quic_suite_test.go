package quic

import (
	"bytes"
	"io"
	"log"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

func TestQuicGo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "QUIC Suite")
}

var mockCtrl *gomock.Controller

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())

	// reset the sync.Once
	connMuxerOnce = *new(sync.Once)
})

var _ = BeforeSuite(func() {
	log.SetOutput(io.Discard)
})

func areServersRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*baseServer).run")
}

func areTransportsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*Transport).listen")
}

var _ = AfterEach(func() {
	mockCtrl.Finish()
	Eventually(areServersRunning).Should(BeFalse())
	Eventually(areTransportsRunning()).Should(BeFalse())
})
