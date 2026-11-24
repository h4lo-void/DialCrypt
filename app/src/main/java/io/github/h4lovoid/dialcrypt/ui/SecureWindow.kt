package io.github.h4lovoid.dialcrypt.ui

import android.app.Activity
import android.os.Build
import android.view.View
import android.view.WindowManager

/** Window hardening applied to every activity of the app. */
object SecureWindow {
    fun apply(activity: Activity) {
        val window = activity.window
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // No system keyboard may ever appear in this app.
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
        if (Build.VERSION.SDK_INT >= 31) {
            window.setHideOverlayWindows(true)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            activity.setRecentsScreenshotEnabled(false)
        }
        if (Build.VERSION.SDK_INT >= 34) {
            window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
    }
}
