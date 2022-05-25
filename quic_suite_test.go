package quic

import (
	"bytes"
	"io/ioutil"
	"log"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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
	log.SetOutput(ioutil.Discard)
})

var _ = AfterEach(func() {
	Eventually(areConnsRunning).Should(BeFalse())
	Eventually(areClosedConnsRunning).Should(BeFalse())
	Eventually(areServersRunning).Should(BeFalse())
	Eventually(arePacketHandlerMapsRunning).Should(BeFalse())
	mockCtrl.Finish()
})

func areConnsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*connection).run")
}

func areClosedConnsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*closedLocalConn).run")
}

func areServersRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*baseServer).run")
}

func arePacketHandlerMapsRunning() bool {
	var b bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Contains(b.String(), "quic-go.(*packetHandlerMap).listen")
}
