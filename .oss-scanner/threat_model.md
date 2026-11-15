# Threat model

quic-go is a QUIC and HTTP/3 implementation, used as both client and server. Everything received from the network (UDP packets and the frames and HTTP/3 messages they carry) is untrusted and may come from a malicious peer.
