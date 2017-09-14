package benchmark

import (
	"flag"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/ginkgo/reporters/stenographer"
	"github.com/onsi/ginkgo/types"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	size    int // file size in MB, will be read from flags
	samples int // number of samples for Measure, will be read from flags

	averageTCPTransferRate float64
)

const tcpMeasurementLabel = "TCP transfer rate [MB/s]"

func TestBenchmark(t *testing.T) {
	RegisterFailHandler(Fail)
	reporter := &myReporter{}
	RunSpecsWithDefaultAndCustomReporters(t, "Benchmark Suite", []Reporter{reporter})
}

func init() {
	flag.IntVar(&size, "size", 50, "data length (in MB)")
	flag.IntVar(&samples, "samples", 6, "number of samples")
	flag.Parse()
}

type myReporter struct {
	Reporter
}

var _ Reporter = &myReporter{}

func newReporter() Reporter {
	return &myReporter{reporters.NewDefaultReporter(config.DefaultReporterConfig, stenographer.New(true, true))}
}

func (r *myReporter) SpecSuiteWillBegin(config.GinkgoConfigType, *types.SuiteSummary) {}
func (r *myReporter) BeforeSuiteDidRun(*types.SetupSummary)                           {}
func (r *myReporter) SpecWillRun(*types.SpecSummary)                                  {}
func (r *myReporter) AfterSuiteDidRun(*types.SetupSummary)                            {}
func (r *myReporter) SpecSuiteDidEnd(*types.SuiteSummary)                             {}

func (r *myReporter) SpecDidComplete(specSummary *types.SpecSummary) {
	if !specSummary.IsMeasurement {
		return
	}
	transferRate, ok := specSummary.Measurements[tcpMeasurementLabel]
	if !ok {
		return
	}
	averageTCPTransferRate = transferRate.Average
}
