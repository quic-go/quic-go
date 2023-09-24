package testutils

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client Session Cache", func() {
	It("scales the duration", func() {
		Expect(os.Setenv(TimescaleFactorEnv, "42")).To(Succeed())
		defer os.Unsetenv(TimescaleFactorEnv)
		Expect(ScaleDuration(time.Second)).To(Equal(42 * time.Second))
	})

	It("doesn't scale the duration if the environment variable is not set", func() {
		Expect(os.Unsetenv(TimescaleFactorEnv)).To(Succeed()) // might be set on CI
		Expect(ScaleDuration(time.Second)).To(Equal(time.Second))
	})
})
