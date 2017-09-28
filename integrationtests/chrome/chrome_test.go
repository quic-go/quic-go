package chrome_test

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("Chrome tests", func() {
	for i := range protocol.SupportedVersions {
		version = protocol.SupportedVersions[i]

		Context(fmt.Sprintf("with quic version %s", version), func() {
			It("downloads a small file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/downloadtest?num=1&len=%d", dataLen),
					waitForDone,
				)
			})

			It("downloads a large file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/downloadtest?num=1&len=%d", dataLongLen),
					waitForDone,
				)
			})

			It("loads a large number of files", func() {
				chromeTest(
					version,
					"https://quic.clemente.io/downloadtest?num=4&len=100",
					waitForDone,
				)
			})

			It("uploads a small file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/uploadtest?num=1&len=%d", dataLen),
					waitForNUploaded(1),
				)
			})

			It("uploads a large file", func() {
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/uploadtest?num=1&len=%d", dataLongLen),
					waitForNUploaded(1),
				)
			})

			It("uploads many small files", func() {
				num := protocol.MaxStreamsPerConnection + 20
				chromeTest(
					version,
					fmt.Sprintf("https://quic.clemente.io/uploadtest?num=%d&len=%d", num, dataLen),
					waitForNUploaded(num),
				)
			})
		})
	}
})
