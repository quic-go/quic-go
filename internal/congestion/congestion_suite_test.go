package congestion

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCongestion(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Congestion Suite")
}
