package quicvarint_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestQuicVarint(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "QUIC Varint Suite")
}
