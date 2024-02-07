# crypto

This package contains a few crypto primitives used by QUIC. Most of them are forks of standard library packages, and the package structure is modeled after the standard library. Unfortunately, standard library crypto doesn't perform well enough for a high-performance QUIC implementation, especially in terms of allocations (see [tracking issue](https://github.com/quic-go/quic-go/issues/3663)).

Long-term, it would be nice to upstream these changes.
