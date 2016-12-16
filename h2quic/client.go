package h2quic

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/idna"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"
)

type quicClient interface {
	OpenStream(protocol.StreamID) (utils.Stream, error)
	Close() error
	Listen() error
}

// Client is a HTTP2 client doing QUIC requests
type Client struct {
	mutex             sync.Mutex
	cryptoChangedCond sync.Cond

	hostname        string
	encryptionLevel protocol.EncryptionLevel

	client              quicClient
	headerStream        utils.Stream
	highestOpenedStream protocol.StreamID
	requestWriter       *requestWriter

	responses map[protocol.StreamID]chan *http.Response
}

// NewClient creates a new client
func NewClient(hostname string) (*Client, error) {
	c := &Client{
		hostname:            authorityAddr("https", hostname),
		highestOpenedStream: 3,
		responses:           make(map[protocol.StreamID]chan *http.Response),
	}
	c.cryptoChangedCond = sync.Cond{L: &c.mutex}

	var err error
	c.client, err = quic.NewClient(c.hostname, c.cryptoChangeCallback, c.versionNegotiateCallback)
	if err != nil {
		return nil, err
	}

	go c.client.Listen()
	return c, nil
}

func (c *Client) handleStreamCb(session *quic.Session, stream utils.Stream) {
	utils.Debugf("Handling stream %d", stream.StreamID())
}

func (c *Client) cryptoChangeCallback(isForwardSecure bool) {
	c.cryptoChangedCond.L.Lock()
	defer c.cryptoChangedCond.L.Unlock()

	if isForwardSecure {
		c.encryptionLevel = protocol.EncryptionForwardSecure
		utils.Debugf("is forward secure")
	} else {
		c.encryptionLevel = protocol.EncryptionSecure
		utils.Debugf("is secure")
	}
	c.cryptoChangedCond.Broadcast()
}

func (c *Client) versionNegotiateCallback() error {
	var err error
	// once the version has been negotiated, open the header stream
	c.headerStream, err = c.client.OpenStream(3)
	if err != nil {
		return err
	}
	c.requestWriter = newRequestWriter(c.headerStream)
	return nil
}

// Do executes a request and returns a response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// TODO: add port to address, if it doesn't have one
	if req.URL.Scheme != "https" {
		return nil, errors.New("quic http2: unsupported scheme")
	}
	if authorityAddr("https", req.Host) != c.hostname {
		utils.Debugf("%s vs %s", req.Host, c.hostname)
		return nil, errors.New("h2quic Client BUG: Do called for the wrong client")
	}

	c.mutex.Lock()
	c.highestOpenedStream += 2
	dataStreamID := c.highestOpenedStream
	for c.encryptionLevel != protocol.EncryptionForwardSecure {
		c.cryptoChangedCond.Wait()
	}
	_, err := c.client.OpenStream(dataStreamID)
	if err != nil {
		return nil, err
	}
	err = c.requestWriter.WriteRequest(req, dataStreamID)
	if err != nil {
		return nil, err
	}
	c.mutex.Unlock()

	// TODO: get the response

	return nil, nil
}

// copied from net/transport.go

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		port = "443"
		if scheme == "http" {
			port = "80"
		}
		host = authority
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}
