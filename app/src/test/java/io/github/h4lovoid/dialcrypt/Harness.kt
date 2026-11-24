package io.github.h4lovoid.dialcrypt

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.ui.ProvideAppLanguage
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardScaffold
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import io.github.h4lovoid.dialcrypt.ui.theme.Palette

/** Same shell as the app (language, theme, in-app keyboard), around a single screen. */
@Composable
fun Harness(language: AppLanguage, host: InputHost, content: @Composable () -> Unit) {
    ProvideAppLanguage(language) {
        DialCryptTheme {
            CompositionLocalProvider(LocalInputHost provides host) {
                Box(Modifier.fillMaxSize().background(Palette.Background)) {
                    KeyboardScaffold(host, content = content)
                }
            }
        }
    }
}
