package fjson_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFjson(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Fjson Suite")
}
