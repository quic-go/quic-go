Here’s a rough design for where I landed with this. In the spirit of “smaller interfaces are better”:

## Notes

Currently, an `http3.Server` handles listening on a UDP port, accepting incoming QUIC connections, negotiating the `h3` ALPN, and then handling HTTP/3 requests from each QUIC session.

One possible way to separate these is to have a QUIC server that negotaties the `h3` ALPN and passes the QUIC session to an `http3.Server` for request routing.

Currently, `http3.Server` takes over the QUIC session and makes certain assumptions about the format of incoming streams and frames. This complicates sharing the same QUIC connection with other protocols, like WebTransport.

The current `http3.Server` implements a translation layer between H3/QUIC and the stdlib `http` package semantics.

- Should the `http3.Server` “own” the QUIC connection, or should it delegate that to another layer?
- Where is the appropriate place to demultiplex non-H3 protocols on an H3/QUIC connection?

From the client perspective, it might be easier to reason about an H3-capable QUIC connection with an alternative API like `http.RoundTripper` that hides H3 entirely from the client, but exposes it via interface assertion to clients who wish to piggyback other protocols on an HTTP/3 connection.

Alternatively, the `http3` package could define a `Handler` interface, which acts as a demultiplexer for H3/QUIC sessions:

```go
type Handler interface {
	ServeHTTP3(Request)
	ServeStream(quic.Session, quic.ReceiveStream, uint64)
	ServeFrame(quic.Session, quic.ReceiveStream, uint64)
}
```

- What goroutine would each handler be ran on?
- Would it be better if the caller controlled parallelism?

```go
package http3

// ParseNextFrame parses an HTTP/3 frame from r.
// For known frame types it will parse the full frame header
// (a varint type followed by a varint length).
// For unknown frame types, it will stop reading after parsing the frame type.
func ParseNextFrame(r io.Reader) (Frame, error)
```

### Extensions

If an `http.Handler` implements an `http3.Extension` interface, an `http3.Server` could delegate unhandled streams, frames, and datagrams to the extension. It would be the responsibility of the extension to close the stream or QUIC session in an error. A hypothetical `Extension` interface:

```go
type Extension interface {
	Settings() Settings
	HandleStream(quic.Session, quic.ReceiveStream, uint64)
	HandleFrame(quic.Session, quic.ReceiveStream, uint64)
	HandleDatagram(quic.Session, []byte)
}
```

A WebTransport handler could wrap an `http.Handler` to provide WebTransport functionality via the `Extension` interface:

```go
package webtransport

type Handler struct {
	http.Handler
	// private fields
}

var _ http3.Extension = &Handler{}
```

## API

### `http3.Server`

To enable HTTP/3 extensions, I propose adding a new field to `http3.Server`: `Requester`. If set, it allows callers to intercept an accepted `quic.EarlySession` and provide an `http3.Requester`. It would default to `http3.Accept`, a new exported func that would tie together the QUIC session with a QPACK decoder and some other state (see below).

```go
	// If set, the server will call Requester for each accepted QUIC session.
	// It is the responsibility of the function to return a valid Requester.
	// If Requester returns an error, the server will close the QUIC session.
	// If nil, http3.Open will be used.
	Requester func(quic.EarlySession, Settings) (Requester, error)

	// Other functions?
	HandleConn func(quic.EarlySession) (quic.EarlySession, error)
	HandleStream func(quic.EarlySession, quic.ReceiveStream, uint64) (quic.ReceiveStream, error)
	HandleFrame func(quic.EarlySession, quic.ReceiveStream, uint64) (quic.ReceiveStream, error)

	// Handlers?
	StreamHandlers map[uint64]func(quic.EarlySession, quic.ReceiveStream) quic.ReceiveStream
	FrameHandlers map[uint64]func(quic.EarlySession, quic.ReceiveStream) quic.ReceiveStream
```

Second, add a flag to `Server` to enable the [extended CONNECT method](https://datatracker.ietf.org/doc/html/rfc8441) (necessary for WebTransport or WebSockets):

```go
	// Enable support for extended CONNECT method.
	// If set to true, the server will support CONNECT requests with a :path and :protocol header.
	EnableConnectProtocol bool
```

### `http3.Requester`

A `Requester` is responsible for providing HTTP requests to the server.

The default implementation wraps a QUIC session and handles H3 framing, request and response body streaming, and translation to/from `http` semantics. It accepts streams and datagrams, (de)multiplexing them to the relevant H3 request sessions.

The `http3` package would provide a default `Accept()` func to create a `Requester` from a QUIC session. It sets up initial state, opens the unidirectional control stream, and sends the H3 settings frame.

A WebTransport extension, for example, could override `(Server).Requester` to provide a WebTransport-aware `Requester`, and dispatch incoming WT streams and datagrams to the appropriate H3 session.

```go
// Requester represents a server-side HTTP/3 connection.
// Implementations may implement other interfaces.
type Requester interface {
	AcceptHTTP() (*http.Request, http.ResponseWriter, error)
	io.Closer
}

// Accept takes a QUIC session and HTTP/3 settings, and returns a Requester.
// It opens the control stream and sends the initial H3 settings frame,
// returning an error if either fail. The returned Requestor is ready to use.
func Accept(session quic.EarlySession, settings Settings) (Requester, error) {
	...
}
```

A `Requester` can be extended to support additional features, e.g. `interface Pusher { ... }`.

### `http3.Conn`

Internally, the default implementation of `Requester` sits on top of `http3.Conn`, which combines a `quic.EarlySession` with a QPACK handler and some other state. Both H3 client and server connections would use `Conn`.

It can be created from a quic.EarlySession via `http3.Open(quic.EarlySession, http3.Settings) (Conn, error)`.

Internally, a `Conn` holds:

- `quic.EarlySession`
- H3 settings
- Peer settings
- Control stream
- Peer control stream
- `qpack.Decoder`
- QPACK encoder and decoder streams
- Push streams

```go
type Conn interface {
	AcceptStream(ctx) (http3.Stream, error)
	AcceptUniStream(ctx) (http3.ReceiveStream, error)
	OpenStream() (http3.Stream, error)
	OpenUniStream(streamType uint64) (http3.SendStream, error)

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	SupportsDatagrams() bool
	ReadDatagram() ([]byte, error)
	WriteDatagram([]byte) error

	DecodeHeaders(io.Reader) (http.Header, error)

	PeerSettings() (http3.Settings, error)

	io.Closer
}

// Necessary between Requester and Conn?
type ServerConn interface {
	AcceptRequest(ctx) (http3.Request, error)
	Conn
}
```

### `http3.Stream`

- the parent http3.Conn
- a QUIC stream

```go
type Stream {
	ReceiveStream
	SendStream
}

type ReceiveStream interface {
	Conn() Conn
	StreamType() uint64
	io.Reader
}

type SendStream interface {
	Conn() Conn
	StreamType() uint64
	io.Writer
	io.Closer
}
```

### `http3.Frame`

- There can be an `http3.UnknownFrame` which parses only the frame type and stops.

```go
type Frame interface {
	FrameType() uint64
	Payload() io.ReadCloser
}
```

`Frame` may also implement `FrameLength() protocol.ByteCount` and `io.WriterTo`.

`Payload` may also implement `Size() protocol.ByteCount`.

Concrete implementations of http3.Frame MAY implement other methods.

### `http3.Request`

An [`http3.Request`](https://www.ietf.org/archive/id/draft-ietf-quic-http-34.html#name-http-message-exchanges) would be created and used by a client and a server. It would contain:

- an `http3.Stream`
- headers
- trailers
- authority
- method
- request body

It can be created from an `http3.Stream` via:

```go
http3.NewRequest(http3.Stream, http.Header) (http3.Request, error)
```

An `http3.Server` could handle an `http3.Request` with:

```go
(Server).ServeHTTP3(http3.Request) error
```

#### Datagrams

An `http3.Request` can vend [datagram contexts](https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-datagram-contexts) via two methods, which supply a `DatagramContext`:

```go
	// AcceptDatagramContext receives a datagram context from a peer.
	// This allows a server, for instance, to start receiving datagrams on a
	// client-initiated datagram context.
	AcceptDatagramContext() (DatagramContext, error)

	// RegisterDatagramContext allocates a new datagram context for the request.
	// It returns an error if a context cannot be allocated or datagrams are not enabled.
	// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_conte
	RegisterDatagramContext() (DatagramContext, error)

	// DatagramNoContext signals to the server that datagrams associated with this request
	// will not use datagram context IDs.
	// It returns an error if a context cannot be allocated or datagrams are not enabled.
	// Multiple calls will return the same database context.
	// Calling DatagramContext after DatagramNoContext will return an error.
	// https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-the-register_datagram_no_co
	DatagramNoContext() (DatagramContext, error)
```

A `DatagramContext` provides the necessary multiplexing to allow different applications to [coexist](https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-03.html#name-multiplexing) on the same HTTP/3 request stream.

```go
type DatagramContext interface {
	ContextID() uint64 // Necessary?
	ReadDatagram() ([]byte, error)
	WriteDatagram([]byte) error
	io.Closer
}
```

### Misc

- `http3.Settings` is a `map[uint64]uint64` with some helper methods.
- `http3.Frame` is `interface { FrameType() uint64 }`
- `http3.SettingsFrame` is a `Frame`, etc.
