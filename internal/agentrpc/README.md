# Agent policy-sync transport

`agentrpc` uses a long-lived bidirectional `net.Conn` with newline-delimited JSON. It is policy synchronization only, never BGP. Each policy has a monotonic sequence. Durable applied and peer ACK cursors are supplied to `NewSession` after reconnect. Duplicate applied policies are ACKed without redelivery.

`MaxMessageBytes` bounds framing and `MaxInFlight` enforces sender backpressure. Production TCP connections require mTLS outside this package. A permission-restricted Unix socket is preferred on one host. Cursors must be persisted atomically with the policy effects they acknowledge.
