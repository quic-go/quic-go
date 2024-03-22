package hkdf_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHkdf(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "HKDF Suite")
}
