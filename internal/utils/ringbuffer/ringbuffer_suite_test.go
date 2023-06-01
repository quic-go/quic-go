package ringbuffer

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTestdata(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ringbuffer suite")
}
