package io.github.h4lovoid.dialcrypt.ui

import android.content.res.Configuration
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.compose.LocalOnBackPressedDispatcherOwner
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ProvidedValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import java.util.Locale

/**
 * Makes every stringResource inside [content] resolve in the chosen language. The localized context
 * no longer wraps the activity, so the activity's result registry (permission requests) and back
 * dispatcher are passed down explicitly; otherwise they would resolve to null inside [content].
 */
@Composable
fun ProvideAppLanguage(language: AppLanguage, content: @Composable () -> Unit) {
    val base = LocalContext.current
    val registryOwner = LocalActivityResultRegistryOwner.current
    val backOwner = LocalOnBackPressedDispatcherOwner.current
    val tag = language.tag
    if (tag == null) {
        content()
        return
    }
    val localized = remember(base, tag) {
        val config = Configuration(base.resources.configuration)
        config.setLocale(Locale.forLanguageTag(tag))
        base.createConfigurationContext(config)
    }
    val values = buildList<ProvidedValue<*>> {
        add(LocalContext provides localized)
        add(LocalConfiguration provides localized.resources.configuration)
        registryOwner?.let { add(LocalActivityResultRegistryOwner provides it) }
        backOwner?.let { add(LocalOnBackPressedDispatcherOwner provides it) }
    }
    CompositionLocalProvider(*values.toTypedArray(), content = content)
}
