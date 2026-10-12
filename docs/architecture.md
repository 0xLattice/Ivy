# Architecture

Ivy turns an untrusted byte stream into bounded records attributed to peer keys.
Authentication proves key control, not application authority.

```text
caller: authority, validation, storage, protocol meaning
                         |
Ivy: admission, sessions, routing, content, relay
                         |
byte streams: built-in TCP, caller-supplied, or configured carrier
```

## Connections

A connection is a `TransportConnection`: an ordered, reliable byte stream to one
peer that delivers bytes only when asked. Ivy's TCP listener and dialer supply
such streams, and a caller supplies its own through `reserveInboundAdmission`,
`accept`, and `connect(to:over:)`. Framing, byte budgets, the handshake, and
sessions sit above the stream and are the same for all of them. Dialing an
address taken from routing is TCP only.

Inbound capacity is reserved by global and netgroup limits, keyed on the
observed address, before anything is requested from a stream. A rejected stream
is never read, so it cannot buffer protocol input while waiting for the Ivy
actor. Capacity is a hard cap: Ivy rejects excess peers rather than evicting
an authenticated connection by reputation.

A pending connection is absent from routing, delegates, content, and application
messages. Promotion requires a signed transcript over both identities, fresh
nonces, route binding, and bounded metadata, followed by the initiator's signed
finish.

Application records bind sender, receiver, session ID, sequence, and payload.
Receive sequences strictly increase. Simultaneous sessions for one peer and
role converge on the smaller session ID. Records are signed but not encrypted;
confidentiality and forward secrecy belong above or below Ivy.

Wire/session protocol v9 rejects v8 during authentication. V9 introduces
multi-frame complete-Volume replies, which cannot safely share the older
one-frame Volume contract.

### Adding to the wire without a new version

The session version changes only when an existing record or message changes.
Everything else is an addition, and an addition needs no version:

- An addition is a new message tag. An existing message never changes its
  encoding or its meaning.
- Ivy sends a new message only to a session its caller names. Whether a peer
  speaks it is the application's to learn (its own hello) and to tell Ivy by
  naming the peer; Ivy's hello carries no capabilities.
- A message whose tag this version does not know is ignored: the session
  stays up and nothing is recorded against the peer. A known message that
  does not decode still ends the session as a signed protocol violation.

An ignored message costs what any message costs before it is understood: its
signature and sequence are checked and its bytes counted as received. It is
bounded as every message is, by the negotiated frame size and the inbound
byte budget, and it is cheaper than a known message nobody wanted. Peers that
predate this rule (through 14.0.0) end the session on an unknown tag, which is
why the second point is a rule and not a courtesy.

Treat every authenticated endpoint connection as an independent availability
zone, not a verdict about the peer. Application timeouts, unavailable content,
and caller-reported deficiency leave the session open. Only transport safety
failures such as invalid authentication, signed protocol violations, or hard
bound exhaustion close it.

## Bounds

- Each node advertises the maximum frame body it will accept (inbound) in its
  handshake; the default is 4 MiB and it is operator-tunable via
  `protocolMaxFrameSize`. A node never sends a frame larger than the peer
  advertised it will accept, and on a relayed route it is further capped at the
  carrier connection's negotiated size. Inbound framing is validated against the
  node's own local cap.
- Each connection's inbound byte budget scales with the local frame cap: it may
  hold at most two maximum frame bodies plus a header (2·cap + 4). One node-wide
  byte budget also covers bytes actually received in partial frames, relayed
  records, and queued records; its default is 64 MiB and is operator-tunable via
  `maxInboundBufferedBytes`. Exhaustion closes the affected connection without
  peer blame.
- Canonical session metadata is limited to 64 KiB.
- Strings, collections, connections, netgroups, pending requests, waiters,
  candidates, routing entries, provider hints, and relay routes are bounded.
- Content framing overhead is subtracted before storage materializes bytes.
- A complete Volume is at most 64 MiB and 65,535 members. Its ordered chunks
  share one request, root, authenticated endpoint session, and node run; partial
  assemblies reserve their declared size from a 128 MiB node-wide receive cap.
  Source materializations pessimistically reserve the same bounded capacity, so
  concurrent serving cannot multiply the per-Volume limit.
- Each connection owns its inbound reader task, so close cancels cooperative
  work. Local and remote content callbacks share one concurrency cap; a
  callback that ignores cancellation keeps its slot until it actually exits.
- A physical dial keeps its connection-cap reservation until the underlying
  NIO future completes, including across stop and restart.

Ivy serves any authenticated peer and never rate-limits its own requests.
Tally records peer-global traffic evidence and compares peers only when
content requests wait for a serving slot: waiting peers share freed slots in
proportion to the verified content they served this node, and a peer with no
history still advances. Ivy does not evict an authenticated connection by
score. Evidence decays, and application content deficiency remains root-scoped
rather than becoming global blame.

## Application protocols

Ivy's generic records and exact content exchange are enough to compose gossip,
sync, and retrieval. Broadcast messages announce gossip to current peers;
directed messages carry sync control; content requests retrieve the selected
bytes. Gossip identity, deduplication, forwarding, sync semantics, CID
validation, and storage remain caller policy.

## Routing and content

Overlay mode uses correlated `findNode` responses from authenticated Kademlia
peers. Address scope, mode, identity work, connection capacity, and netgroup
policy apply before admission. Referrals are lookup candidates, not routing
entries; only a successful authenticated session promotes an endpoint into
routing. Private-network mode exposes only authenticated direct messages; it
does not run discovery, routing, provider, content, relay, or broadcast services.
A referral must use a globally routable IP. A private or loopback
self-advertisement is usable only when it exactly matches the observed socket
address. Pinned mode admits one endpoint identity. Ivy has no peer-exchange
protocol. STUN contributes an observed host only; configure `externalAddress`
with an IP literal when the externally reachable TCP port differs from
`listenPort`.

A content request is exactly:

```text
rootCID + deduplicated selected identifiers
```

Identifiers are non-empty ASCII wire strings, so equality is byte-exact without
assigning them semantics. The source must return that set exactly once within the direct or relayed byte
budget. Duplicate, extra, missing, oversized, unsolicited, and unexpected-peer
responses are unavailable, never partial.

A Volume request names only its root. The source returns one complete bounded
Volume, which Ivy canonically orders and streams in sequential frames. Each
frame still obeys the same negotiated route cap (4 MiB by default). Competing providers assemble
independently, and replacement sessions, gaps, duplicates, conflicting stream
metadata, and malformed archives discard only that provider's attempt. Ivy
returns no `AttributedVolumeResponse` until one archive is complete and contains
the requested root. Identifiers and bytes remain opaque: Ivy neither validates
content addressing nor interprets or traverses a DAG. A request waiting for
capacity never times out. `requestTimeout` starts once a content request holds
its serving slot, and once a Volume request holds both its slot and its byte
reservation (its authorization callback runs before that, untimed); from then
Ivy cancels serving at the deadline. Blocked writers release their reservation, while a storage
callback that ignores cancellation remains counted until it actually exits.

A bundle request (added after v9 under the rule above, so sent only to the
sessions `fetchVolumeBundle` is given) names a root and asks for every Volume
the source bundles under it. The source names the bundle's Volume roots, the root's own first;
what a bundle means is the application's. Ivy authorizes, reads, reserves,
times and streams each Volume exactly as a requested one, in turn, then sends
`volumeBundleEnd`. Between two Volumes the request gives up its serving slot
and queues for the next, so under contention a bundle is served no faster
than the same Volumes requested one at a time. A Volume that cannot
be sent is left out; an end with no Volume before it says the peer holds no
bundle for the root, which is distinct from `contentUnavailable`. The
requester keeps every Volume completed before the answer ended, however it
ended, each counted against its in-flight Volume budget until the fetch
returns: a bundle is never required to be complete, and the caller fetches
what it still lacks as single Volumes. The result says whether the answer
ended with the peer's end marker; whether to ask again a peer whose answer did
not is the caller's to decide.

Equal requests coalesce across cached providers, fresh discovery, fallback, and
the wire request. `requestTimeout` bounds that whole fetch for its callers;
timed-out backend or network work remains counted until it exits. A content
selection asks known providers, then fresh discovery, then the peers already
connected, under that deadline; a Volume fetch asks known providers, then the
peers already connected, then fresh discovery, with no deadline over the whole
fetch. Provider hints are bounded and expiring: each is a peer's own announcement or a
referral from a lookup answer, never a note that a peer served the root; a
source's referrals never evict an announcement. A failed local dial
does not erase a hint, and a failed address does not suppress a healthy address
for the same identity.

The caller may report content deficient after validation. Ivy then suppresses
that peer briefly for that root; it does not create peer-global blame, close the
connection, or affect messages and other roots. A later fetch can use another
connected provider, fresh discovery, or fallback as a separate availability
zone.

## Relay and attribution

Outbound relay initiation uses configured carriers. A target may accept an
inbound route offered by another authenticated direct peer without configuring
that peer as its carrier. The route grants transport only: endpoint records
remain signed end to end, so the offer cannot change either endpoint identity
or place the carrier in endpoint routing. A carrier forwards each route in
arrival order to its exact destination session, waits only until
`requestTimeout` for writability, and then retires that route.

Ivy attributes a violation only after verifying the charged peer's signature.
Signed malformed endpoint payloads remain attributable through relay. Unsigned
bytes are unattributed, and relay-controlled replay or sequence failure is
ambiguous because a carrier can replay a valid record.

Timeouts, failed dials, unavailable content, and local queue pressure remain
route or service state, not protocol violations.

## Lifecycle

Lifecycle calls execute in order. Each run has a generation; dials, reconnects,
lookups, routes, provider queries, and content leaders also carry generations or
tokens. `stop()` invalidates them and resumes waiters, so old completions cannot
mutate a newer run. A callback retains its exact authenticated session and
cannot send a reply through a replacement session for the same peer.

See [correctness-invariants.md](correctness-invariants.md) for the normative
review laws.
