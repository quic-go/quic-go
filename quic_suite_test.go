package quic

import (
	"io/ioutil"
	"log"
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
	mockCtrl.Finish()
})
