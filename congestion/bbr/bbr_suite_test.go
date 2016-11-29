package bbr

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCongestion(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BBR Suite")
}
