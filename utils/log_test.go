package utils

import (
	"bytes"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Log", func() {
	var (
		b *bytes.Buffer
	)

	BeforeEach(func() {
		b = bytes.NewBuffer([]byte{})
		out = b
	})

	AfterEach(func() {
		out = os.Stdout
		SetLogLevel(LogLevelNothing)
	})

	It("log level nothing", func() {
		SetLogLevel(LogLevelNothing)
		Debugf("debug")
		Infof("info")
		Errorf("err")
		Expect(b.Bytes()).To(Equal([]byte("")))
	})

	It("log level err", func() {
		SetLogLevel(LogLevelError)
		Debugf("debug")
		Infof("info")
		Errorf("err")
		Expect(b.Bytes()).To(Equal([]byte("err\n")))
	})

	It("log level info", func() {
		SetLogLevel(LogLevelInfo)
		Debugf("debug")
		Infof("info")
		Errorf("err")
		Expect(b.Bytes()).To(Equal([]byte("info\nerr\n")))
	})

	It("log level debug", func() {
		SetLogLevel(LogLevelDebug)
		Debugf("debug")
		Infof("info")
		Errorf("err")
		Expect(b.Bytes()).To(Equal([]byte("debug\ninfo\nerr\n")))
	})

	It("says whether debug is enabled", func() {
		Expect(Debug()).To(BeFalse())
		SetLogLevel(LogLevelDebug)
		Expect(Debug()).To(BeTrue())
	})

	It("reads log level from env", func() {
		Expect(logLevel).To(Equal(LogLevelNothing))
		os.Setenv(logEnv, "1")
		readLoggingEnv()
		Expect(logLevel).To(Equal(LogLevelDebug))
	})

	It("does not error reading invalid log levels from env", func() {
		Expect(logLevel).To(Equal(LogLevelNothing))
		os.Setenv(logEnv, "")
		readLoggingEnv()
		Expect(logLevel).To(Equal(LogLevelNothing))
		os.Setenv(logEnv, "asdf")
		readLoggingEnv()
		Expect(logLevel).To(Equal(LogLevelNothing))
	})
})
