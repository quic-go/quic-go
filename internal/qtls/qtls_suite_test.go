package qtls

import (
	"testing"

	gomock "github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestQTLS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "qtls Suite")
}

var mockCtrl *gomock.Controller

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())
})

var _ = AfterEach(func() {
	mockCtrl.Finish()
})
