package protocol_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestProtocol(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Protocol Suite")
}
