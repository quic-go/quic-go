package http3

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

func TestHttp3(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "HTTP/3 Suite")
}

var mockCtrl *gomock.Controller

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())
})

var _ = AfterEach(func() {
	mockCtrl.Finish()
})
