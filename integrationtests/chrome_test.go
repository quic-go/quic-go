package integrationtests

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Chrome tests", func() {
	It("loads a simple hello world page using quic", func() {
		err := wd.Get("https://quic.clemente.io/hello")
		Expect(err).NotTo(HaveOccurred())
		source, err := wd.PageSource()
		Expect(err).NotTo(HaveOccurred())
		Expect(source).To(ContainSubstring("Hello, World!\n"))
	})
})
