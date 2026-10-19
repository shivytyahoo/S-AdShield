# AdShield architecture

```text
Android/TV
    |
    v
VpnService
    |
    +--> TUN packet reader
    |       |
    |       +--> DNS parser
    |       +--> Blocklist matcher
    |       +--> Allowlist
    |       +--> DNS cache
    |       +--> Upstream resolver (protected socket)
    |       +--> Anti-detect surrogate path (v0.7.0)
    |               |
    |               +--> stub DNS answer (10.10.10.3) for blocked A queries
    |               +--> TcpRelay: minimal userspace TCP for the stub IP
    |               +--> StubHttpServer: empty-but-valid surrogate resources
    |
    +--> Stats / local database
    |
    +--> UI
```

The central product rule is: filtering happens locally. The application should not
become a general-purpose traffic tunnel to a third-party server.

For HTTPS ad delivery, DNS filtering can only block destinations that can be
identified at the DNS/domain level. It cannot guarantee removal of ads that are
served from the same host/CDN as first-party content. Browser content filtering
and some app-specific mechanisms are separate layers.

## Anti-detect surrogate mode (v0.7.0, default ON)

**Problem.** Most "Ad blocker detected" walls do not detect the blocker
itself — they detect that a *bait request* (ad pixel, ad script, tracking
pixel) **failed**. With plain NXDOMAIN blocking, the browser reports a
network error and the site's detection script shows the wall / blocks the
video.

**Fix (same technique as uBlock Origin's `$redirect` surrogates, adapted to
a DNS-level blocker).** Blocked domains resolve to a local stub IP
(`10.10.10.3`, routed into the TUN) instead of NXDOMAIN. A minimal
userspace TCP stack (`TcpRelay`) completes the HTTP handshake there and
`StubHttpServer` answers with empty-but-*valid* resources:

| Bait type | Surrogate response |
|---|---|
| ad JS (`.js`, `Accept: *javascript*`) | 200 + tiny JS defining `adsbygoogle` / `googletag` / `ga` / `gtag` |
| ad image | 200 + 1x1 transparent GIF |
| ad frame / HTML | 200 + blank page |
| anything else | 204 No Content |

The bait request *succeeds*, so `onerror` / failed-`fetch` probes never
fire — while no real ad is ever fetched, rendered or displayed. AAAA
queries for blocked domains get an empty NOERROR to nudge dual-stack
clients onto IPv4; non-HTTP ports (notably 443/TLS) get a fast RST,
matching the old fail-fast behaviour.

**Honest limits.**
- HTTPS bait cannot be stubbed without the user installing a trusted CA
  (TLS to the stub IP cannot complete) — those probes still fail as
  before. Full HTTPS filtering (AdGuard-style, user-installed CA) is the
  Phase-2 answer and needs an explicit user decision (security trade-off).
- Server-side / playback-behaviour checks (e.g. "did the ad segment
  actually play") cannot be fooled at the DNS layer.
- The Streaming EXTREME pack (SSAI middlemen: IMA/DAI, FreeWheel…)
  remains separately toggleable: on a few IMA-based players, stubbing
  the ad SDK is not enough and the pack should be turned OFF for that
  site instead.
