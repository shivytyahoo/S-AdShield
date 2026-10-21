package com.adshield

/**
 * v0.9.0 "Universal" — embedded MITM site list: the world's major adult
 * video sites. On first run after upgrade these are merged into the
 * user's MITM domains (their own entries keep priority), so the full
 * HTTPS cleaning + in-page protection works on all of them out of the
 * box — no per-site setup. The list stays fully editable in the app.
 *
 * Deliberately EXCLUDED: creator/payment platforms (OnlyFans, Fansly,
 * ManyVids, Clips4Sale) where interception could disturb purchases,
 * uploads or creator logins — the generic DNS shield still covers
 * their ad/tracker domains.
 */
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
    "sextb.net", "camwhores.tv", "maturetube.com", "ashemaletube.com",
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
