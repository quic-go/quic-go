package testutils

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "testutils Suite")
}
