package simnet

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Simnet is a simulated network that manages connections between nodes
// with configurable network conditions.
type Simnet struct {
	Router Router

	mx    sync.Mutex
	links []*SimulatedLink
}

// NodeBiDiLinkSettings defines the bidirectional link settings for a network node.
// It specifies separate configurations for downlink (incoming) and uplink (outgoing)
// traffic, allowing asymmetric network conditions to be simulated.
type NodeBiDiLinkSettings struct {
	// Downlink configures the settings for incoming traffic to this node
	Downlink LinkSettings
	// Uplink configures the settings for outgoing traffic from this node
	Uplink LinkSettings

	// Latency specifies a fixed network delay for downlink packets only
	// If both Latency and LatencyFunc are set, LatencyFunc takes precedence
	Latency time.Duration

	// LatencyFunc computes the network delay for each downlink packet
	// This allows variable latency based on packet source/destination
	// If nil, Latency field is used instead
	LatencyFunc func(Packet) time.Duration
}

func (n *Simnet) Close() error {
	n.mx.Lock()
	defer n.mx.Unlock()

	var errs error
	for _, link := range n.links {
		if err := link.Close(); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("failed to close some links: %w", errs)
	}
	return nil
}

// NewEndpoint adds a node to the network.
func (n *Simnet) NewEndpoint(addr *net.UDPAddr, linkSettings NodeBiDiLinkSettings) *SimConn {
	link := &SimulatedLink{
		DownlinkSettings: linkSettings.Downlink,
		UplinkSettings:   linkSettings.Uplink,
		Latency:          linkSettings.Latency,
		LatencyFunc:      linkSettings.LatencyFunc,
		UploadPacket:     n.Router,
	}
	c := NewBlockingSimConn(addr, link)
	link.Start()

	n.mx.Lock()
	n.links = append(n.links, link)
	n.mx.Unlock()

	n.Router.AddNode(addr, link)
	return c
}
