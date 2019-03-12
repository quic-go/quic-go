package http3

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestHttp3(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "HTTP/3 Suite")
}
