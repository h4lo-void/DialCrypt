package io.github.h4lovoid.dialcrypt.ui.model

import android.content.Context
import java.util.Locale

/**
 * Verification words come from the string-array "sas_words" (256 entries per language, supplied
 * separately). While the array is missing, only the three-digit numbers are shown.
 */
object SasWords {
    fun word(context: Context, index: Int): String? {
        val res = context.resources
        val id = res.getIdentifier("sas_words", "array", context.packageName)
        if (id == 0) return null
        return res.getStringArray(id).getOrNull(index)
    }

    fun number(index: Int): String = String.format(Locale.ROOT, "%03d", index.coerceIn(0, 255))
}
