package ackhandler

import (
	"math/rand"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AckHandler Suite")
}

var mockCtrl *gomock.Controller

var _ = BeforeSuite(func() {
	rand.Seed(GinkgoRandomSeed())
})

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())
})

var _ = AfterEach(func() {
	mockCtrl.Finish()
})
