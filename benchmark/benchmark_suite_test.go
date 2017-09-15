package benchmark

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/olekukonko/tablewriter"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/types"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

var (
	size    int // file size in MB, will be read from flags
	samples int // number of samples for Measure, will be read from flags

	netemAvailable         bool
	averageTCPTransferRate float64
)

const (
	device = "dev lo" // the network device the netem rules will be applied to
	// set test and context labels, so that our custom Ginkgo reporter can find them
	tcpContextLabel   = "with TLS/TCP"
	quicContextLabel  = "with QUIC %d"
	transferRateLabel = "transfer rate [MB/s]"
)

var reporter = &myReporter{}

func TestBenchmark(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecsWithDefaultAndCustomReporters(t, "Benchmark Suite", []Reporter{reporter})
}

func init() {
	flag.IntVar(&size, "size", 50, "data length (in MB)")
	flag.IntVar(&samples, "samples", 6, "number of samples")
	flag.Parse()

	_, err := exec.LookPath("tc")
	netemAvailable = err == nil
	fmt.Println("netemAvaliable", netemAvailable)
}

func clearNetem() {
	if netemAvailable {
		status := execNetem("tc qdisc show #device")
		if strings.Contains(status, "netem") {
			execNetem("tc qdisc del #device root")
		}
	}
}

func execNetem(cmd string) string {
	if len(cmd) == 0 {
		return ""
	}
	r := strings.NewReplacer("#device", "dev lo")
	cmd = r.Replace(cmd)
	w := strings.Split(cmd, " ")
	command := exec.Command(w[0], w[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{}
	command.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred())
	Eventually(session).Should(gexec.Exit(0))
	return string(session.Out.Contents())
}

type networkCondition struct {
	Description string
	Command     string
}

var conditions = []networkCondition{
	{Description: "direct transfer"},
	{Description: "10ms RTT", Command: "tc qdisc add #device root netem delay 5ms"},
	{Description: "50ms RTT", Command: "tc qdisc add #device root netem delay 25ms"},
	{Description: "100ms RTT", Command: "tc qdisc add #device root netem delay 50ms"},
	{Description: "400ms RTT", Command: "tc qdisc add #device root netem delay 200ms"},
	{Description: "10ms ± 1ms RTT", Command: "tc qdisc add #device root netem delay 5ms 1ms"},
	{Description: "50ms ± 5ms RTT", Command: "tc qdisc add #device root netem delay 25ms 5ms"},
	{Description: "10ms RTT, 1% packet loss", Command: "tc qdisc add #device root netem delay 5ms drop 1%"},
	{Description: "10ms RTT, 5% packet loss", Command: "tc qdisc add #device root netem delay 5ms drop 5%"},
	{Description: "100ms RTT, 1% packet loss", Command: "tc qdisc add #device root netem delay 50ms drop 1%"},
	{Description: "100ms RTT, 5% packet loss", Command: "tc qdisc add #device root netem delay 50ms drop 5%"},
}

type measurementSeries map[string]float64

var _ = BeforeSuite(func() {
	clearNetem()
})

var _ = AfterSuite(func() {
	clearNetem()
	reporter.printResult()
})

type myReporter struct {
	Reporter

	results map[string]measurementSeries
}

var _ Reporter = &myReporter{}

func (r *myReporter) SpecSuiteWillBegin(config.GinkgoConfigType, *types.SuiteSummary) {}
func (r *myReporter) BeforeSuiteDidRun(*types.SetupSummary)                           {}
func (r *myReporter) SpecWillRun(*types.SpecSummary)                                  {}
func (r *myReporter) AfterSuiteDidRun(*types.SetupSummary)                            {}
func (r *myReporter) SpecSuiteDidEnd(*types.SuiteSummary)                             {}

func (r *myReporter) SpecDidComplete(specSummary *types.SpecSummary) {
	if !specSummary.IsMeasurement {
		return
	}
	cond := specSummary.ComponentTexts[2]
	ver := specSummary.ComponentTexts[3]
	transferRate, ok := specSummary.Measurements[transferRateLabel]
	if !ok {
		return
	}
	r.addResult(cond, ver, transferRate.Average)
	if ver == tcpContextLabel {
		averageTCPTransferRate = transferRate.Average
	}
}

func (r *myReporter) addResult(cond, ver string, transferRate float64) {
	if r.results == nil {
		r.results = make(map[string]measurementSeries)
	}
	if _, ok := r.results[cond]; !ok {
		r.results[cond] = make(measurementSeries)
	}
	r.results[cond][ver] = transferRate
}

func (r *myReporter) printResult() {
	table := tablewriter.NewWriter(os.Stdout)
	header := []string{"", "TCP"}
	for _, v := range protocol.SupportedVersions {
		header = append(header, "QUIC "+strconv.Itoa(int(v)))
	}
	table.SetHeader(header)
	table.SetCaption(true, fmt.Sprintf("Based on %d samples of %d MB.\nAll values in MB/s.", samples, size))

	for _, cond := range conditions {
		data := make([]string, len(protocol.SupportedVersions)+2)
		data[0] = cond.Description
		tcpRate, ok := r.results[cond.Description][tcpContextLabel]
		if !ok {
			data[1] = "-"
		} else {
			data[1] = fmt.Sprintf("%.2f", tcpRate)
		}
		for i, ver := range protocol.SupportedVersions {
			val, ok := r.results[cond.Description][fmt.Sprintf(quicContextLabel, ver)]
			var out string
			if !ok {
				out = "-"
			} else {
				out = fmt.Sprintf("%.2f", val) + " (" + fmt.Sprintf("%.1f", 100*val/tcpRate) + "%)"
			}
			data[i+2] = out
		}
		table.Append(data)
	}
	table.Render()
}
