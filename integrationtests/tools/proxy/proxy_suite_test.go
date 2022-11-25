package quicproxy

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestQuicGo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "QUIC Proxy")
}
