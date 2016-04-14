package handshake

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestQuicGo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Handshake Suite")
}
