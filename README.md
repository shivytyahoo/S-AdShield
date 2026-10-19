# AdShield — Phase 1 Android / Android TV MVP

This repository starts a cross-platform, system-wide ad-blocking product.

## Current phase

The Android project contains:

- Kotlin UI (plain Android views — no Compose, keeps the APK tiny)
- Android `VpnService` with a working local DNS-filtering engine
- Foreground protection service
- TV launcher category
- Built-in starter ad/tracker domain list
- DNS packet parser / NXDOMAIN response helper

## Engine status (build of 2026-10-06)

The originally shipped ZIP only opened the TUN and dropped every packet,
which would have black-holed all DNS. This build adds the minimal real
engine so the APK is actually testable:

- TUN advertises DNS server 10.10.10.1 and routes only that /32, so only
  DNS traffic enters the TUN; all other traffic flows normally.
- IPv4/UDP DNS queries to 10.10.10.1:53 are parsed; blocked names get an
  NXDOMAIN reply, everything else is forwarded through a `protect()`-ed
  socket to 8.8.8.8 (fallback 1.1.1.1) and the real reply is written back.

Still MVP limits: IPv4/UDP DNS only (no IPv6, no TCP DNS fallback, no DNS
cache), and no per-app bypass or statistics yet.
DNS filtering can only block domains identified at DNS level; ads served
from the same host/CDN as content (e.g. in-stream Prime/YouTube app ads)
cannot be blocked this way.

## Blocklist (v0.2.0)

Bundled list: `app/src/main/assets/blocklist.txt` — StevenBlack unified
hosts (https://github.com/StevenBlack/hosts, MIT), 72,232 unique domains
fetched 2026-10-06, plus 21 built-in fallback domains. Matching walks
parent domains (`ads.doubleclick.net` matches `doubleclick.net`).
Video/content domains (youtube.com, googlevideo.com, netflix.com,
primevideo.com) were verified NOT to be in the list before shipping.

## Build

Open this folder in Android Studio and let Gradle sync.

Then:

```bash
./gradlew assembleDebug
```

APK output:

`app/build/outputs/apk/debug/app-debug.apk`

## Roadmap

### Phase 2 — real filtering engine
1. TUN IPv4/IPv6 packet parser
2. UDP DNS interception
3. Protected upstream DNS resolver
4. DNS cache
5. Blocklist matcher using suffix trie
6. Allowlist
7. Per-app bypass
8. Statistics
9. Auto-update signed lists

### Phase 3 — Android TV optimization
- Leanback/TV UI
- Very low RAM mode
- CPU-efficient matching
- Boot persistence / always-on VPN guidance
- Remote-friendly controls
- No unnecessary animations

### Phase 4 — Windows
Build the same filtering core behind a Windows network interception layer.
The Windows implementation should use a proper system networking mechanism rather
than a browser-only extension.

## Security design

- No remote VPN server is required for DNS filtering.
- Resolver sockets must be protected from the VPN to avoid loops.
- Blocklist updates should be authenticated/signed.
- No browsing-history upload.
- Statistics should be local by default.

## UI / branding refresh

v0.3.1 now includes a dark, modern dashboard with animated protection state,
live query/blocked/block-rate counters, rounded information cards, phone/TV
focus-friendly controls, a custom shield vector icon, and the footer
“Developed with love by Shiv”.

## Filter-source policy

AdShield is a DNS-level blocker. It can consume domain/hosts-style data, but
uBlock Origin's full browser engine contains filter syntax for cosmetic and
scriptlet rules that this VPN DNS engine cannot execute. The project therefore
keeps a source registry in `app/src/main/assets/filter_sources.txt` rather than
blindly copying unrelated browser-engine code. Candidate upstreams include
uBlock Origin/uAssets, AdGuard filters, and EasyList; each imported list must be
converted to supported DNS/domain rules and its license/attribution preserved.

This project does not implement unlocking paid features, fake purchases,
license/entitlement bypass, or anti-tamper bypassing.

## Merged ad-network coverage (v0.5.1, 2026-10-08)

The targeted rules from the v0.4.1 ad-network build (`assets/ad_networks.txt`,
kept as-is) are merged with the v0.5.0 network shield
(`assets/network_blocklist.txt`) and the StevenBlack bundled list. All three
load at startup; matching walks parent domains. Deliberate omissions stay:
whole-list imports that would also block youtube.com / facebook.com are not
used, so content and social apps keep working.

## uBlock uAssets (DNS-converted) — v0.5.2, 2026-10-08

`assets/ublock_domains.txt` is generated from uBlock Origin's uAssets lists
(filters, privacy, badware, resource-abuse). Only plain "block this host"
network rules were converted to DNS entries (1,329 new domains after dedupe
against the existing lists). Rules with paths, redirects, removeparam/replace
rewrites, site limits, and all cosmetic/scriptlet rules were dropped — a DNS
engine cannot execute them. Whole-service parents (youtube.com, facebook.com,
google.com, googleapis.com, ...) were excluded so apps keep working.
The uBlock Origin extension itself is browser-only (Firefox/Chromium/GeckoView)
and is NOT embedded; this is its filter data, applied system-wide over DNS.

## EXTREME pack (v0.6.0, 2026-10-08)

- `assets/hagezi_domains.txt`: HaGeZi Multi PRO (domains-only, GitHub) —
  180k extra domains after dedupe; the aggressive ULTIMATE edition was
  rejected on purpose (documented to break e.g. Facebook apps).
- `assets/streaming_blocklist.txt`: SSAI middlemen (Google DAI/IMA, FreeWheel,
  SpotX, Innovid, SpringServe, Yospace, Amazon Publisher Services) behind the
  in-app STREAMING EXTREME toggle. Some IMA-based players refuse to start
  playback when their ad SDK is unreachable; the toggle exists for that case.
- Bypass hardening: well-known public resolver IPs (Google/Cloudflare/Quad9/
  OpenDNS/AdGuard/CleanBrowsing/Control D/DNS.WATCH/Level3) are routed into
  the TUN and answered by this engine; non-DNS traffic to them is dropped,
  so hardcoded/encrypted DNS falls back to filterable system DNS. Known DoH
  hostnames are in `network_blocklist.txt`.
- Lists now load on a background thread (built-in starter set guards the
  first seconds) so startup never stalls on ~250k entries.
Honest limit, unchanged: ads stitched into the video stream itself (SSAI
proper, same CDN as the film) cannot be separated by DNS. This pack blocks
the ad *decision/middleman* calls around the stream, which is everything a
DNS engine can reach.

Merged from Shiv's v0.5.3 streaming-safe build (2026-10-08): the reserved
`assets/streaming_safe_rules.txt` profile is bundled and loaded too. It carries
only guidance comments today (never block streaming services' own domains
wholesale) — the same rule this project's lists already follow.

## Anti-detect surrogate mode (v0.7.0)

**Problem it solves:** "Ad blocker detected — disable your ad blocker to watch
this video" walls. Sites don't see the blocker; they see that a *bait request*
(ad pixel / ad script) **failed** (NXDOMAIN → network error → wall).

**How it works** (same idea as uBlock Origin's `$redirect` surrogates, adapted
to a DNS-level blocker): blocked domains now resolve to a local stub IP
`10.10.10.3` instead of NXDOMAIN. A tiny userspace TCP stack (`TcpRelay`)
answers HTTP there and `StubHttpServer` returns empty-but-*valid* resources —
tiny JS defining `adsbygoogle`/`googletag`, a 1x1 GIF, a blank page, or
204 No Content. The bait request *succeeds*, so the wall never fires, and no
real ad is ever fetched or shown. Toggle: **ANTI-DETECT** button in the app
(default ON). See `docs/ARCHITECTURE.md` for the full design and honest
limits (HTTPS bait needs a user-installed CA — planned Phase 2).
