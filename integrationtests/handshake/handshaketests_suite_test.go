package handshaketests

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestHandshakes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Handshake integration tests")
}
