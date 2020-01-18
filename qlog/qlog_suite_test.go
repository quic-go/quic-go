package qlog

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestQlog(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "qlog Suite")
}
