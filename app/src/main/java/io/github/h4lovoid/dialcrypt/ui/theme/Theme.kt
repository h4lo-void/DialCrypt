package io.github.h4lovoid.dialcrypt.ui.theme

import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Quiet dark palette: graphite surfaces, one muted champagne accent, desaturated status colors.
 * Status colors are used together with words, never alone, and only on small marks and thin lines.
 * Surfaces come in three close steps above the graphite background:
 * [Surface] for cards, [SurfaceHigh] for fields and inset blocks, [SurfaceTop] for floating layers.
 */
object Palette {
    val Background = Color(0xFF111213)
    val Surface = Color(0xFF161719)
    val SurfaceHigh = Color(0xFF1D1E21)
    val SurfaceTop = Color(0xFF25262A)
    val Outline = Color(0xFF8E8D88)
    /** Hairlines and dividers only; never used for text. */
    val OutlineSoft = Color(0xFF2A2B2F)
    val OnSurface = Color(0xFFE9E7E2)
    val OnSurfaceMuted = Color(0xFFA3A19B)
    /** Soft champagne: the only accent in the app. */
    val Accent = Color(0xFFD2C6AC)
    val AccentContainer = Color(0xFF2B2924)
    val Warn = Color(0xFFC9A66B)
    val Ok = Color(0xFF8FB09A)
    val Danger = Color(0xFFD1766E)
    val DangerBackground = Color(0xFF171112)
    val DangerContainer = Color(0xFF1E1516)
    val Key = Color(0xFF232427)
    val KeySpecial = Color(0xFF2F3033)
    val OutgoingBubble = Color(0xFF2A2825)
}

/** Spacing scale. Every gap in the app is one of these. */
object Space {
    val xs = 4.dp
    val sm = 8.dp
    val md = 12.dp
    val lg = 16.dp
    val xl = 24.dp
}

/** Corner radius scale. */
object Radius {
    val sm = 8.dp
    val md = 12.dp
    val lg = 16.dp
    val xl = 24.dp
}

/** Six close grey steps for contact avatars. Initials reach at least 4.5:1 on each. */
object AvatarPalette {
    val colors = listOf(
        Color(0xFF343539),
        Color(0xFF3A3B3F),
        Color(0xFF404144),
        Color(0xFF464749),
        Color(0xFF2F3033),
        Color(0xFF4B4C4E),
    )

    fun indexFor(id: Long): Int = Math.floorMod(id, colors.size.toLong()).toInt()

    fun forId(id: Long): Color = colors[indexFor(id)]
}

enum class Tone { NEUTRAL, WARN, OK, DANGER }

fun Tone.color(): Color = when (this) {
    Tone.NEUTRAL -> Palette.OnSurfaceMuted
    Tone.WARN -> Palette.Warn
    Tone.OK -> Palette.Ok
    Tone.DANGER -> Palette.Danger
}

/** Soft fill behind text or icons of the same tone. */
fun Tone.container(): Color = when (this) {
    Tone.NEUTRAL -> Palette.SurfaceHigh
    else -> color().copy(alpha = 0.10f)
}

private val Scheme = darkColorScheme(
    primary = Palette.Accent,
    onPrimary = Palette.Background,
    primaryContainer = Palette.AccentContainer,
    onPrimaryContainer = Palette.Accent,
    secondary = Palette.Accent,
    onSecondary = Palette.Background,
    background = Palette.Background,
    onBackground = Palette.OnSurface,
    surface = Palette.Surface,
    onSurface = Palette.OnSurface,
    surfaceVariant = Palette.SurfaceHigh,
    onSurfaceVariant = Palette.OnSurfaceMuted,
    outline = Palette.Outline,
    outlineVariant = Palette.OutlineSoft,
    error = Palette.Danger,
    onError = Palette.Background,
)

/** Medium weights and a little extra letter and line spacing keep titles calm. */
private val DialCryptTypography = Typography(
    displaySmall = TextStyle(fontSize = 36.sp, lineHeight = 46.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
    headlineMedium = TextStyle(fontSize = 28.sp, lineHeight = 38.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.2.sp),
    headlineSmall = TextStyle(fontSize = 24.sp, lineHeight = 34.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
    titleLarge = TextStyle(fontSize = 22.sp, lineHeight = 30.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
    titleMedium = TextStyle(fontSize = 16.sp, lineHeight = 24.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.15.sp),
    titleSmall = TextStyle(fontSize = 14.sp, lineHeight = 22.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.15.sp),
    bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 26.sp, fontWeight = FontWeight.Normal, letterSpacing = 0.15.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 22.sp, fontWeight = FontWeight.Normal, letterSpacing = 0.15.sp),
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 18.sp, fontWeight = FontWeight.Normal, letterSpacing = 0.2.sp),
    labelLarge = TextStyle(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.15.sp),
    labelMedium = TextStyle(fontSize = 12.sp, lineHeight = 18.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
    labelSmall = TextStyle(fontSize = 11.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
)

@Composable
fun DialCryptTheme(content: @Composable () -> Unit) {
    // The app is always dark; the system theme setting is deliberately ignored.
    MaterialTheme(colorScheme = Scheme, typography = DialCryptTypography) {
        // Text outside a Surface would otherwise fall back to black on black.
        CompositionLocalProvider(LocalContentColor provides Palette.OnSurface, content = content)
    }
}
