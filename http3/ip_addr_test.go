package http3

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUDPAddrForIPs(t *testing.T) {
	addr, err := udpAddrForIPs("udp", "example.org:443", "example.org", 443, []net.IPAddr{
		{IP: net.IPv4(192, 0, 2, 1)},
	})
	require.NoError(t, err)
	assert.Equal(t, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, addr)
}

func TestUDPAddrForIPsEmpty(t *testing.T) {
	addr, err := udpAddrForIPs("udp", "example.org:443", "example.org", 443, nil)
	require.Error(t, err)
	assert.Nil(t, addr)
	var dnsErr *net.DNSError
	require.ErrorAs(t, err, &dnsErr)
	assert.Equal(t, "example.org", dnsErr.Name)
}
