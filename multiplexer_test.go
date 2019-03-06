package quic

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Client Multiplexer", func() {
	It("adds a new packet conn ", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 8, nil)
		Expect(err).ToNot(HaveOccurred())
	})

	It("errors when adding an existing conn with a different connection ID length", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 5, nil)
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 6, nil)
		Expect(err).To(MatchError("cannot use 6 byte connection IDs on a connection that is already using 5 byte connction IDs"))
	})

	It("errors when adding an existing conn with a different stateless rest key", func() {
		conn := newMockPacketConn()
		_, err := getMultiplexer().AddConn(conn, 7, []byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		_, err = getMultiplexer().AddConn(conn, 7, []byte("raboof"))
		Expect(err).To(MatchError("cannot use different stateless reset keys on the same packet conn"))
	})
})
