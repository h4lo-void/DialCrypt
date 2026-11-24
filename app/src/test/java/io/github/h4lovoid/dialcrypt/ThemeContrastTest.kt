package io.github.h4lovoid.dialcrypt

import androidx.compose.ui.graphics.Color
import io.github.h4lovoid.dialcrypt.ui.theme.AvatarPalette
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import io.github.h4lovoid.dialcrypt.ui.theme.color
import io.github.h4lovoid.dialcrypt.ui.theme.container
import kotlin.math.pow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Text must stay readable (at least 4.5:1) on every surface it is drawn on, and the palette must stay quiet. */
class ThemeContrastTest {
    private fun linear(c: Float): Double =
        if (c <= 0.03928f) c / 12.92 else ((c + 0.055) / 1.055).pow(2.4)

    private fun luminance(c: Color): Double =
        0.2126 * linear(c.red) + 0.7152 * linear(c.green) + 0.0722 * linear(c.blue)

    private fun ratio(a: Color, b: Color): Double {
        val la = luminance(a)
        val lb = luminance(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    /** What a translucent fill looks like on top of an opaque surface. */
    private fun over(top: Color, base: Color): Color {
        val a = top.alpha
        return Color(
            red = top.red * a + base.red * (1 - a),
            green = top.green * a + base.green * (1 - a),
            blue = top.blue * a + base.blue * (1 - a),
        )
    }

    private fun assertReadable(label: String, text: Color, background: Color) {
        val r = ratio(text, background)
        assertTrue(label + " is only " + "%.2f".format(r) + ":1", r >= 4.5)
    }

    /** HSV saturation, 0 for greys and 1 for a pure colour. */
    private fun saturation(c: Color): Double {
        val hi = maxOf(c.red, c.green, c.blue).toDouble()
        val lo = minOf(c.red, c.green, c.blue).toDouble()
        return if (hi == 0.0) 0.0 else (hi - lo) / hi
    }

    @Test
    fun bodyTextIsReadableOnEverySurface() {
        val surfaces = listOf(Palette.Background, Palette.Surface, Palette.SurfaceHigh, Palette.SurfaceTop)
        surfaces.forEach { s ->
            assertReadable("text on " + s, Palette.OnSurface, s)
            assertReadable("muted on " + s, Palette.OnSurfaceMuted, s)
        }
        // Placeholders and disabled labels sit on fields and buttons.
        assertReadable("outline on field", Palette.Outline, Palette.SurfaceHigh)
        assertReadable("outline on black", Palette.Outline, Palette.Background)
        assertReadable("text on outgoing bubble", Palette.OnSurface, Palette.OutgoingBubble)
        assertReadable("muted on outgoing bubble", Palette.OnSurfaceMuted, Palette.OutgoingBubble)
        assertReadable("outline on top layer", Palette.Outline, Palette.SurfaceTop)
    }

    @Test
    fun statusColorsAreReadableAsTextAndOnTheirOwnTint() {
        listOf(Palette.Accent, Palette.Warn, Palette.Ok, Palette.Danger).forEach { c ->
            listOf(Palette.Background, Palette.Surface, Palette.SurfaceHigh).forEach { assertReadable("status " + c + " on " + it, c, it) }
        }
        listOf(Tone.WARN, Tone.OK, Tone.DANGER).forEach { tone ->
            val tint = over(tone.container(), Palette.Surface)
            assertReadable("badge " + tone, tone.color(), tint)
            assertReadable("banner " + tone, tone.color(), Palette.Background)
        }
        assertReadable("danger on red screen", Palette.Danger, Palette.DangerBackground)
        assertReadable("danger on red card", Palette.Danger, Palette.DangerContainer)
        assertReadable("accent on its container", Palette.Accent, Palette.AccentContainer)
        assertReadable("main button label", Palette.Accent, Palette.AccentContainer)
        assertReadable("shift key icon and Done label", Palette.Accent, Palette.AccentContainer)
        assertReadable("side button label", Palette.OnSurface, Palette.Surface)
        assertReadable("text on red screen", Palette.OnSurface, Palette.DangerBackground)
        assertReadable("muted on red screen", Palette.OnSurfaceMuted, Palette.DangerBackground)
        assertReadable("text on red card", Palette.OnSurface, Palette.DangerContainer)
    }

    @Test
    fun accentIsAQuietNeutralAndBackgroundsAreGraphite() {
        assertTrue("accent is too colourful", saturation(Palette.Accent) <= 0.25)
        listOf(Palette.Background, Palette.Surface, Palette.SurfaceHigh, Palette.SurfaceTop, Palette.Key, Palette.KeySpecial).forEach {
            assertTrue("surface " + it + " is too colourful", saturation(it) <= 0.15)
        }
        // Three close steps: each surface is a little lighter than the one below it.
        val steps = listOf(Palette.Background, Palette.Surface, Palette.SurfaceHigh, Palette.SurfaceTop).map { luminance(it) }
        assertEquals(steps.sorted(), steps)
        assertTrue("surfaces are not close", steps.last() < 0.03)
        assertTrue("background is not near black", steps.first() < 0.01)
    }

    @Test
    fun statusColorsAreDesaturated() {
        assertTrue(saturation(Palette.Ok) <= 0.30)
        assertTrue(saturation(Palette.Warn) <= 0.50)
        assertTrue(saturation(Palette.Danger) <= 0.50)
        // Full-screen warning backgrounds stay dark.
        assertTrue(luminance(Palette.DangerBackground) < 0.01)
        assertTrue(luminance(Palette.DangerContainer) < 0.02)
    }

    @Test
    fun avatarColorsAreSixDistinctGreysWithReadableInitials() {
        assertEquals(6, AvatarPalette.colors.size)
        assertEquals(6, AvatarPalette.colors.toSet().size)
        AvatarPalette.colors.forEach {
            assertReadable("initials on " + it, Palette.OnSurface, it)
            assertTrue("avatar " + it + " is not grey", saturation(it) <= 0.10)
        }
    }

    @Test
    fun avatarColorDependsOnlyOnTheContactId() {
        assertEquals(AvatarPalette.forId(3), AvatarPalette.forId(3))
        assertEquals(AvatarPalette.forId(1), AvatarPalette.forId(7))
        (-20L..20L).forEach { id -> assertTrue(AvatarPalette.forId(id) in AvatarPalette.colors) }
        assertEquals(6, (1L..6L).map { AvatarPalette.forId(it) }.toSet().size)
    }
}
