package io.github.h4lovoid.dialcrypt.core

import java.util.Locale

/**
 * ITU-T E.164 country calling codes keyed by lowercase ISO 3166-1 alpha-2 region code.
 * Regions that share a code (the +1 numbering plan, +7, +44 crown dependencies, ...) all map to it.
 * Regions without a single unambiguous code are left out and resolve to null.
 */
object CountryCallingCodes {
    private val TABLE: Map<String, String> = mapOf(
        "ad" to "376", "ae" to "971", "af" to "93", "ag" to "1", "ai" to "1", "al" to "355", "am" to "374", "ao" to "244", "ar" to "54", "as" to "1", "at" to "43", "au" to "61", "aw" to "297", "ax" to "358", "az" to "994",
        "ba" to "387", "bb" to "1", "bd" to "880", "be" to "32", "bf" to "226", "bg" to "359", "bh" to "973", "bi" to "257", "bj" to "229", "bl" to "590", "bm" to "1", "bn" to "673", "bo" to "591", "bq" to "599", "br" to "55", "bs" to "1", "bt" to "975", "bw" to "267", "by" to "375", "bz" to "501",
        "ca" to "1", "cc" to "61", "cd" to "243", "cf" to "236", "cg" to "242", "ch" to "41", "ci" to "225", "ck" to "682", "cl" to "56", "cm" to "237", "cn" to "86", "co" to "57", "cr" to "506", "cu" to "53", "cv" to "238", "cw" to "599", "cx" to "61", "cy" to "357", "cz" to "420",
        "de" to "49", "dj" to "253", "dk" to "45", "dm" to "1", "do" to "1", "dz" to "213",
        "ec" to "593", "ee" to "372", "eg" to "20", "eh" to "212", "er" to "291", "es" to "34", "et" to "251",
        "fi" to "358", "fj" to "679", "fk" to "500", "fm" to "691", "fo" to "298", "fr" to "33",
        "ga" to "241", "gb" to "44", "gd" to "1", "ge" to "995", "gf" to "594", "gg" to "44", "gh" to "233", "gi" to "350", "gl" to "299", "gm" to "220", "gn" to "224", "gp" to "590", "gq" to "240", "gr" to "30", "gt" to "502", "gu" to "1", "gw" to "245", "gy" to "592",
        "hk" to "852", "hn" to "504", "hr" to "385", "ht" to "509", "hu" to "36",
        "id" to "62", "ie" to "353", "il" to "972", "im" to "44", "in" to "91", "io" to "246", "iq" to "964", "ir" to "98", "is" to "354", "it" to "39",
        "je" to "44", "jm" to "1", "jo" to "962", "jp" to "81",
        "ke" to "254", "kg" to "996", "kh" to "855", "ki" to "686", "km" to "269", "kn" to "1", "kp" to "850", "kr" to "82", "kw" to "965", "ky" to "1", "kz" to "7",
        "la" to "856", "lb" to "961", "lc" to "1", "li" to "423", "lk" to "94", "lr" to "231", "ls" to "266", "lt" to "370", "lu" to "352", "lv" to "371", "ly" to "218",
        "ma" to "212", "mc" to "377", "md" to "373", "me" to "382", "mf" to "590", "mg" to "261", "mh" to "692", "mk" to "389", "ml" to "223", "mm" to "95", "mn" to "976", "mo" to "853", "mp" to "1", "mq" to "596", "mr" to "222", "ms" to "1", "mt" to "356", "mu" to "230", "mv" to "960", "mw" to "265", "mx" to "52", "my" to "60", "mz" to "258",
        "na" to "264", "nc" to "687", "ne" to "227", "nf" to "672", "ng" to "234", "ni" to "505", "nl" to "31", "no" to "47", "np" to "977", "nr" to "674", "nu" to "683", "nz" to "64",
        "om" to "968",
        "pa" to "507", "pe" to "51", "pf" to "689", "pg" to "675", "ph" to "63", "pk" to "92", "pl" to "48", "pm" to "508", "pr" to "1", "ps" to "970", "pt" to "351", "pw" to "680", "py" to "595",
        "qa" to "974",
        "re" to "262", "ro" to "40", "rs" to "381", "ru" to "7", "rw" to "250",
        "sa" to "966", "sb" to "677", "sc" to "248", "sd" to "249", "se" to "46", "sg" to "65", "sh" to "290", "si" to "386", "sj" to "47", "sk" to "421", "sl" to "232", "sm" to "378", "sn" to "221", "so" to "252", "sr" to "597", "ss" to "211", "st" to "239", "sv" to "503", "sx" to "1", "sy" to "963", "sz" to "268",
        "tc" to "1", "td" to "235", "tg" to "228", "th" to "66", "tj" to "992", "tk" to "690", "tl" to "670", "tm" to "993", "tn" to "216", "to" to "676", "tr" to "90", "tt" to "1", "tv" to "688", "tw" to "886", "tz" to "255",
        "ua" to "380", "ug" to "256", "us" to "1", "uy" to "598", "uz" to "998",
        "vc" to "1", "ve" to "58", "vg" to "1", "vi" to "1", "vn" to "84", "vu" to "678",
        "wf" to "681", "ws" to "685",
        "xk" to "383",
        "ye" to "967", "yt" to "262",
        "za" to "27", "zm" to "260", "zw" to "263",
    )

    /** Returns the calling code for [iso] (any letter case), or null when it is blank or unknown. */
    fun forIso(iso: String?): String? {
        val key = iso?.trim()?.lowercase(Locale.ROOT) ?: return null
        return TABLE[key]
    }
}
