package io.github.h4lovoid.dialcrypt.core

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager

/**
 * Level 1 hardening leaves accessibility services running, and any of them can read the screen:
 * messages, phone numbers and the keys of the built-in keypad. Preparation requires none to be enabled.
 */
internal object AccessibilityCheck {
    /** True only when the system reports no enabled accessibility service; false when it cannot tell. */
    fun noneEnabled(context: Context): Boolean {
        val am = context.getSystemService(AccessibilityManager::class.java) ?: return false
        return try {
            am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).isEmpty()
        } catch (_: RuntimeException) {
            false
        }
    }
}
