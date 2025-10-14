package simnet

import (
	"errors"
	"fmt"
	"net"
)

// Simnet is a simulated network that manages connections between nodes
// with configurable network conditions.
type Simnet struct {
	Router Router

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
}

func (n *Simnet) Start() error {
	for _, link := range n.links {
		link.Start()
	}
	return nil
}

func (n *Simnet) Close() error {
	var errs error
	for _, link := range n.links {
		err := link.Close()
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("failed to close some links: %w", errs)
	}
	return nil
}

func (n *Simnet) NewEndpoint(addr *net.UDPAddr, linkSettings NodeBiDiLinkSettings) *SimConn {
	link := &SimulatedLink{
		DownlinkSettings: linkSettings.Downlink,
		UplinkSettings:   linkSettings.Uplink,
		UploadPacket:     n.Router,
	}
	c := NewBlockingSimConn(addr, link)

	n.links = append(n.links, link)
	n.Router.AddNode(addr, link)
	return c
}
