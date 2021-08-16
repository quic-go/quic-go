package http3

import "context"

// TODO: implement the DATAGRAM draft:
// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html
type DatagramRequestStream interface {
	RequestStream

	// AcceptDatagramContext receives a datagram context from a peer.
	// This allows a server, for instance, to start receiving datagrams on a
	// client-initiated datagram context.
	// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-datagram-contexts.
	AcceptDatagramContext(context.Context) (DatagramContext, error)

	// RegisterDatagramContext allocates a new datagram context for the request.
	// It returns an error if a context cannot be allocated or datagrams are not enabled.
	// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_conte.
	RegisterDatagramContext() (DatagramContext, error)

	// DatagramNoContext signals to the server that datagrams associated with this request
	// will not use datagram context IDs.
	// It returns an error if a context cannot be allocated or datagrams are not enabled.
	// Multiple calls will return the same DatagramContext.
	// The returned DatagramContext will have a context ID of -1.
	// Calling DatagramContext after DatagramNoContext will return an error.
	// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_no_co.
	DatagramNoContext() (DatagramContext, error)
}

// A DatagramHandler can read and write datagrams.
type DatagramHandler interface {
	// ReadDatagram reads a single datagram.
	ReadDatagram() ([]byte, error)

	// WriteDatagram writes a single datagram.
	WriteDatagram([]byte) error
}

// A DatagramContext is a datagram handler with a unique context ID.
// A DatagramContext with a context ID of -1 indicates "no context."
// See https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_no_co.
type DatagramContext interface {
	ContextID() int64
	DatagramHandler
}
