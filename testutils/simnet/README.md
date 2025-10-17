# simnet

This package is based on @MarcoPolo's [simnet](https://github.com/marcopolo/simnet) package.

A small Go library for simulating packet networks in-process. It provides
drop-in `net.PacketConn` endpoints connected through configurable virtual links
with bandwidth, latency, and MTU constraints. Useful for testing networking code
without sockets or root privileges.

- **Drop-in API**: implements `net.PacketConn`
- **Realistic links**: per-direction bandwidth, latency, and MTU
- **Backpressure/buffering**: bandwidth–delay product aware queues
- **Routers**: perfect delivery, fixed-latency, simple firewall/NAT-like routing
- **Deterministic testing**: opt-in `synctest`-based tests for time control


