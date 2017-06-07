# Changelog

## v0.6.0 (unreleased)

- Add a `quic.Config` option for QUIC versions
- Add a `quic.Config` option to request truncation of the connection ID from a server
- Add a `quic.Config` option to configure the source address validation
- Add a `quic.Config` option to configure the handshake timeout
- Changed the log level environment variable to only accept strings ("DEBUG", "INFO", "ERROR"), see [the wiki](https://github.com/lucas-clemente/quic-go/wiki/Logging) for more details.
- Various bugfixes
