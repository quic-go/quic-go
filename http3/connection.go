package http3

import (
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/utils"
)

type connection struct {
	quic.Connection
	logger utils.Logger

	maps *datagrammerMap
	once sync.Once
}

func (c *connection) Datagrammer(s quic.Stream) Datagrammer {
	if !c.Connection.ConnectionState().SupportsDatagrams {
		return nil
	}

	c.once.Do(func() {
		c.maps = newDatagrammerMap(c.Connection, c.logger)
	})

	return c.maps.newStreamAssociatedDatagrammer(s)
}
