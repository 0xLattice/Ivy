# Correctness invariants

Authentication proves a peer key, never application authority.

| ID | Law |
| --- | --- |
| IVY-001 | Inbound capacity is reserved before protocol reads begin. |
| IVY-002 | Pending connections are invisible to routing, delegates, content, and application messages. |
| IVY-003 | Promotion requires the complete route-bound signed handshake and bounded canonical metadata. |
| IVY-004 | Accepted records bind sender, receiver, session, sequence, and payload; sequences never replay or wrap. |
| IVY-005 | Duplicate sessions for one peer and role converge on the smaller session ID. |
| IVY-006 | Endpoint and carrier identities are disjoint; carriers never enter endpoint routing. |
| IVY-007 | Work from an old run, operation, or authenticated session cannot mutate or reply through successor state. |
| IVY-008 | Frames, fields, connections, pending work, routing, hints, routes, and all partial or queued inbound bytes are bounded. |
| IVY-009 | Each node enforces its own frame-body cap (4 MiB default, operator-tunable, handshake-advertised); outbound never exceeds the peer's advertised cap (carrier-minimum on relay). One 64 KiB metadata cap applies on every route. |
| IVY-010 | Exact route overhead is removed before a content source materializes bytes. |
| IVY-011 | Content is request-correlated and exact, or unavailable; partial success is impossible. |
| IVY-012 | Ivy treats non-empty ASCII wire identifiers and bytes as opaque and never traverses or stores a DAG. |
| IVY-013 | Equal fetches coalesce across the whole bounded provider-search pipeline. |
| IVY-014 | Provider records are expiring hints and grant no possession, validity, or authority. |
| IVY-015 | Public discovery returns admitted candidates; only authenticated promotion installs routing state, and there is no PEX. |
| IVY-016 | Outbound relay initiation uses configured carriers; inbound offers grant transport only, every relayed session authenticates both endpoint identities end to end, and carrier forwarding is ordered, exact-session-bound, and deadline-bounded. |
| IVY-017 | Peer-global blame requires that peer's verified signature; carrier-controlled ambiguity remains unattributed. |
| IVY-018 | Queue acceptance does not assert receipt, application acceptance, or durability. |
| IVY-019 | Authorization, content validity, storage, consensus, fees, and settlement remain above Ivy. |
| IVY-020 | Application unavailability or deficient content may change selection for that root, but cannot disconnect or globally condemn an authenticated peer. |
| IVY-021 | A complete Volume is bounded, request/root/session/run-bound, globally reservation-capped on receive and serve, sequentially assembled per provider, and visible only after exact complete decoding. |

Primary coverage: `SessionProtocolTests`, `IvyTopologyTests`,
`InboundAdmissionTests`, `MessageFrameDecoderBoundTests`,
`ContentExchangeTests`, `PendingRequestCapsTests`, `ProviderRefreshTests`,
`ProviderSuppressionTests`, `RoutingIngressHardeningTests`, `RelayIntegrationTests`,
`TransportSeamTests`, and `TCPIntegrationTests`.
