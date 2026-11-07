package com.adshield

/**
 * v0.9.0 "Universal" — embedded MITM site list: the world's major adult
 * video sites. On first run after upgrade these are merged into the
 * user's MITM domains (their own entries keep priority), so the full
 * HTTPS cleaning + in-page protection works on all of them out of the
 * box — no per-site setup. The list stays fully editable in the app.
 *
 * v0.9.3: imggle.net (sextb's poster CDN) added — it publishes an ECH
 * record, so with the VPN off Chrome hides its SNI behind ECH and the
 * carrier lets it through; with plain VPN DNS the SNI is visible and
 * the carrier cuts the connection. Serving it through the MITM relay
 * takes the browser's fragile ECH path out of the loop.
 *
 * v0.9.4: video file hosts added — tubes embed their players from
 * these hosts (F4/StreamWish/FileMoon/Dood/Voe/Streamtape/VidHide),
 * and the player document is where the tap-to-play popunder lives.
 * Those hosts were plain FWD before, so the player page never got
 * the in-page bundle and its window.open ran unopposed. MITM-ing
 * them puts the bundle inside the player document itself. Video
 * bytes (mp4/m3u8) are not HTML, so they pass through untouched.
 *
 * Deliberately EXCLUDED: creator/payment platforms (OnlyFans, Fansly,
 * ManyVids, Clips4Sale) where interception could disturb purchases,
 * uploads or creator logins — the generic DNS shield still covers
 * their ad/tracker domains.
 */
const val EMBEDDED_LIST_VERSION = 3

/**
 * Video file hosts (v0.9.4 list) — their player documents get the
 * player-safe bundle (v0.9.5): same traps, no cosmetic CSS, because
 * the players run an anti-adblock bait div (class ad-banner) that the
 * CSS would hide, and then they refuse to start at all.
 */
val PLAYER_HOSTS: Set<String> = setOf(
    "f4stream.com", "f4scdn.com", "f4s.top",
    "streamwish.to", "streamwish.com",
    "filemoon.sx", "filemoon.to",
    "doodstream.com", "dood.watch",
    "voe.sx", "streamtape.com", "vidhide.com"
)

fun isPlayerHost(host: String): Boolean {
    val h = host.lowercase()
    return PLAYER_HOSTS.any { h == it || h.endsWith(".$it") }
}
val EMBEDDED_MITM_DOMAINS: List<String> = listOf(
    // Mega tubes (Aylo network + independents)
    "pornhub.com", "pornhub.org", "redtube.com", "youporn.com", "tube8.com",
    "thumbzilla.com", "extremetube.com", "keezmovies.com", "spankwire.com",
    "xvideos.com", "xvideos.es", "xvideos2.com", "xnxx.com", "xnxx.es",
    "xhamster.com", "xhamster1.com", "xhamster2.com", "xhamster3.com",
    "xhamster5.com", "xhamster18.com", "xhamster19.com", "xhamsterlive.com",
    "spankbang.com", "beeg.com", "eporner.com", "hqporner.com", "porntrex.com",
    "tnaflix.com", "drtuber.com", "4tube.com", "fux.com", "fuq.com",
    "porn.com", "sex.com", "cliphunter.com", "empflix.com", "hardsextube.com",
    "sunporno.com", "porndig.com", "thisvid.com", "motherless.com",
    "ixxx.com", "txxx.com", "upornia.com", "hclips.com", "ok.xxx",
    "porn300.com", "veporn.com", "h2porn.com", "dinotube.com", "gotporn.com",
    "userporn.com", "porntube.com", "moviefap.com", "playvid.com",
    "sextb.net", "cdn001.imggle.net", "cdn002.imggle.net", "imggle.net",
    // Video file hosts — players embedded by tubes (v0.9.4, tap-popunder fix)
    "f4stream.com", "f4scdn.com", "f4s.top",
    "streamwish.to", "streamwish.com",
    "filemoon.sx", "filemoon.to",
    "doodstream.com", "dood.watch",
    "voe.sx", "streamtape.com", "vidhide.com",
    "camwhores.tv", "maturetube.com", "ashemaletube.com",
    "pornhost.com", "alohatube.com", "fantasti.cc", "efukt.com",
    "tubegalore.com", "xxxbunker.com", "perfectgirls.net", "imagefap.com",
    "sxyprn.com", "tubepornclassic.com", "faphouse.com",
    // Asian / JAV
    "avgle.com", "jable.tv", "missav.com", "supjav.com", "javmost.com",
    "javlibrary.com", "vjav.com", "njav.tv", "fc2.com", "javhd.com",
    "thisav.com",
    // Hentai / anime
    "hanime.tv", "rule34video.com", "hentaihaven.xxx", "hentaigasm.com",
    "nhentai.net", "e-hentai.org",
    // Live cam platforms
    "chaturbate.com", "stripchat.com", "bongacams.com", "livejasmin.com",
    "myfreecams.com", "cam4.com", "imlive.com", "camsoda.com",
    "streamate.com", "flirt4free.com", "visite-x.net", "amateur.tv",
    // Paysites with free sections / tours
    "brazzers.com", "mofos.com", "realitykings.com", "digitalplayground.com",
    "twistys.com", "babes.com", "bangbros.com", "naughtyamerica.com",
    "teamskeet.com", "vixen.com", "blacked.com", "tushy.com", "men.com",
    "seancody.com", "kink.com", "adulttime.com", "letsdoeit.com",
    "metart.com", "nubiles-porn.com", "21sextury.com", "fakehub.com",
    "dorcel.com", "private.com", "x-art.com", "joymii.com", "sexart.com",
    "wowgirls.com", "girlsway.com", "puretaboo.com", "jacquieetmichel.com",
    // VR
    "povr.com", "sexlikereal.com", "czechvr.com", "vrporn.com", "badoinkvr.com"
)
