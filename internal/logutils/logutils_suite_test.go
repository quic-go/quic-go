package logutils

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLogutils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logutils Suite")
}
