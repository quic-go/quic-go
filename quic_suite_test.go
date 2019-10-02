package quic

import (
	"bytes"
	"runtime/pprof"
	"strings"
	"sync"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
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

func areSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*session).run")
}

func areClosedSessionsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*closedLocalSession).run") ||
		strings.Contains(b.String(), "quic-go.(*closedRemoteSession).run")
}

var _ = AfterEach(func() {
	mockCtrl.Finish()
	Eventually(areSessionsRunning).Should(BeFalse())
	Eventually(areClosedSessionsRunning).Should(BeFalse())
})
