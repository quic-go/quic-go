package handshake

import (
	"encoding/asn1"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Token Generator", func() {
	var tokenGen *TokenGenerator

	BeforeEach(func() {
		var err error
		tokenGen, err = NewTokenGenerator()
		Expect(err).ToNot(HaveOccurred())
	})

	It("generates a token", func() {
		ip := net.IPv4(127, 0, 0, 1)
		token, err := tokenGen.NewRetryToken(&net.UDPAddr{IP: ip, Port: 1337}, nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(token).ToNot(BeEmpty())
	})

	It("works with nil tokens", func() {
		token, err := tokenGen.DecodeToken(nil)
		Expect(err).ToNot(HaveOccurred())
		Expect(token).To(BeNil())
	})

	It("accepts a valid token", func() {
		ip := net.IPv4(192, 168, 0, 1)
		tokenEnc, err := tokenGen.NewRetryToken(
			&net.UDPAddr{IP: ip, Port: 1337},
			nil,
		)
		Expect(err).ToNot(HaveOccurred())
		token, err := tokenGen.DecodeToken(tokenEnc)
		Expect(err).ToNot(HaveOccurred())
		Expect(token.RemoteAddr).To(Equal("192.168.0.1"))
		Expect(token.SentTime).To(BeTemporally("~", time.Now(), 100*time.Millisecond))
		Expect(token.OriginalDestConnectionID).To(BeNil())
	})

	It("saves the connection ID", func() {
		tokenEnc, err := tokenGen.NewRetryToken(
			&net.UDPAddr{},
			protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef},
		)
		Expect(err).ToNot(HaveOccurred())
		token, err := tokenGen.DecodeToken(tokenEnc)
		Expect(err).ToNot(HaveOccurred())
		Expect(token.OriginalDestConnectionID).To(Equal(protocol.ConnectionID{0xde, 0xad, 0xbe, 0xef}))
	})

	It("rejects invalid tokens", func() {
		_, err := tokenGen.DecodeToken([]byte("invalid token"))
		Expect(err).To(HaveOccurred())
	})

	It("rejects tokens that cannot be decoded", func() {
		token, err := tokenGen.tokenProtector.NewToken([]byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		_, err = tokenGen.DecodeToken(token)
		Expect(err).To(HaveOccurred())
	})

	It("rejects tokens that can be decoded, but have additional payload", func() {
		t, err := asn1.Marshal(token{RemoteAddr: []byte("foobar")})
		Expect(err).ToNot(HaveOccurred())
		t = append(t, []byte("rest")...)
		enc, err := tokenGen.tokenProtector.NewToken(t)
		Expect(err).ToNot(HaveOccurred())
		_, err = tokenGen.DecodeToken(enc)
		Expect(err).To(MatchError("rest when unpacking token: 4"))
	})

	// we don't generate tokens that have no data, but we should be able to handle them if we receive one for whatever reason
	It("doesn't panic if a tokens has no data", func() {
		t, err := asn1.Marshal(token{RemoteAddr: []byte("")})
		Expect(err).ToNot(HaveOccurred())
		enc, err := tokenGen.tokenProtector.NewToken(t)
		Expect(err).ToNot(HaveOccurred())
		_, err = tokenGen.DecodeToken(enc)
		Expect(err).ToNot(HaveOccurred())
	})

	It("works with an IPv6 addresses ", func() {
		addresses := []string{
			"2001:db8::68",
			"2001:0000:4136:e378:8000:63bf:3fff:fdd2",
			"2001::1",
			"ff01:0:0:0:0:0:0:2",
		}
		for _, addr := range addresses {
			ip := net.ParseIP(addr)
			Expect(ip).ToNot(BeNil())
			raddr := &net.UDPAddr{IP: ip, Port: 1337}
			tokenEnc, err := tokenGen.NewRetryToken(raddr, nil)
			Expect(err).ToNot(HaveOccurred())
			token, err := tokenGen.DecodeToken(tokenEnc)
			Expect(err).ToNot(HaveOccurred())
			Expect(token.RemoteAddr).To(Equal(ip.String()))
			Expect(token.SentTime).To(BeTemporally("~", time.Now(), 100*time.Millisecond))
		}
	})

	It("uses the string representation an address that is not a UDP address", func() {
		raddr := &net.TCPAddr{IP: net.IPv4(192, 168, 13, 37), Port: 1337}
		tokenEnc, err := tokenGen.NewRetryToken(raddr, nil)
		Expect(err).ToNot(HaveOccurred())
		token, err := tokenGen.DecodeToken(tokenEnc)
		Expect(err).ToNot(HaveOccurred())
		Expect(token.RemoteAddr).To(Equal("192.168.13.37:1337"))
		Expect(token.SentTime).To(BeTemporally("~", time.Now(), 100*time.Millisecond))
	})
})
