# sing-snell

[Surge snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) implemented in Go.

## Features

* All complete features except the v5 QUIC proxy.
* Behavior as consistent with the official implementation as possible.
* Performance at least on par with the official implementation.

## Why

Surge believes that being closed-source and not proliferated can keep this protocol
covert, but this is already impossible in 2026. Considering that snell still has
advantages that other random-traffic protocols do not possess, such as multiplexing
support with complete TCP semantics and traffic-characteristic diversity, we made this
instead of reinventing the wheel.

## Herta-Network fork

The public Snell package paths are retained. Shared buffer, address and network
interfaces now come from `github.com/metacubex/sing`, pinned to Herta-Network/sing
commit `a402b0b490ba3514b46e242c0630420da7fec151`. Consumers must repeat that
replacement in their main module because Go does not inherit dependency
replacements. This allows Snell and mihomo to pass packet buffers directly
without maintaining a second sing type identity.

UDP connections expose `PacketBatchWriterWithCount` for v4 clients, v5 servers
and both sides of v6 (raw, unshaped and shaped). Batch progress counts only fully
written encrypted records, including empty datagrams. Up to 64 records share a
vector write. Failed writes close the stream and block scalar/batch retries;
all input buffers are consumed. Scalar writes use the same synchronization and
record encoder. Close can interrupt a blocked writer. Existing error-only batch
interfaces remain available.

Local regression tests cover both directions, HTTP/TLS obfuscation, partial
writes, chunk boundaries, validation without nonce drift, and shutdown. These
checks are not official-server interoperability or performance measurements.
