# Agent policy-sync transport

`agentrpc` uses a long-lived bidirectional `net.Conn` with UTF-8 JSON framed by a 32-bit unsigned big-endian length. It is policy synchronization only, never BGP. Each policy has a monotonic sequence plus an idempotency key. Durable applied and peer ACK cursors are supplied to `NewSession` after reconnect. Duplicate applied policies are ACKed without redelivery.

`MaxMessageBytes` bounds framing and `MaxInFlight` enforces sender backpressure. Production TCP connections require mTLS outside this package. A permission-restricted Unix socket is preferred on one host. Cursors must be persisted atomically with the policy effects they acknowledge.
