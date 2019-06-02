package self_test

import (
	"crypto/tls"
	"math/rand"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	_ "github.com/lucas-clemente/quic-go/integrationtests/tools/testlog"
	"github.com/lucas-clemente/quic-go/internal/testdata"
)

const alpn = "quic-go integration tests"

func getTLSConfig() *tls.Config {
	conf := testdata.GetTLSConfig()
	conf.NextProtos = []string{alpn}
	return conf
}

func getTLSClientConfig() *tls.Config {
	return &tls.Config{
		RootCAs:    testdata.GetRootCA(),
		NextProtos: []string{alpn},
	}
}

func TestSelf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Self integration tests")
}

var _ = BeforeSuite(func() {
	rand.Seed(GinkgoRandomSeed())
})
