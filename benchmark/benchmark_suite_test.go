package benchmark

import (
	"flag"
	"math/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestBenchmark(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Benchmark Suite")
}

var (
	size int // file size in MB, will be read from flags
)

func init() {
	flag.IntVar(&size, "size", 50, "data length (in MB)")
}

var _ = BeforeSuite(func() {
	rand.Seed(GinkgoRandomSeed())

	flag.Parse()
})
