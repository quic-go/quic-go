package publicheader

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestErrorcodes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Public Header Suite")
}
