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
commit `76a402191dfe868fc5e08442a148528100d54534`. Consumers must repeat that
replacement in their main module because Go does not inherit dependency
replacements. This allows Snell and mihomo to pass packet buffers directly
without maintaining a second sing type identity.
