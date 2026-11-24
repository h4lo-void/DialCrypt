package io.github.h4lovoid.dialcrypt.ui.keyboard

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/** Content above, in-app keyboard below whenever an input has focus. */
@Composable
fun KeyboardScaffold(host: InputHost, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(modifier.fillMaxSize()) {
        Box(Modifier.weight(1f).fillMaxWidth()) { content() }
        if (host.active != null) SecureKeyboard(host)
    }
}
