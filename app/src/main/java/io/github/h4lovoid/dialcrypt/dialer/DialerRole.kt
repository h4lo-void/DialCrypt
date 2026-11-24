package io.github.h4lovoid.dialcrypt.dialer

import android.app.role.RoleManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings

/**
 * The default dialer role and the call screening role. The state is always read from
 * [RoleManager]; nothing is stored. The roles are only ever requested through the system consent
 * screen and given back through the system's default apps settings.
 */
object DialerRole {
    /** Launcher entry "Phone", enabled only while the app holds the dialer role. */
    const val PHONE_LAUNCHER = "io.github.h4lovoid.dialcrypt.dialer.PhoneLauncher"

    fun isHeld(c: Context): Boolean = held(c, RoleManager.ROLE_DIALER)

    fun isScreeningHeld(c: Context): Boolean = held(c, RoleManager.ROLE_CALL_SCREENING)

    /** The system consent screen for the dialer role; null when the role is not available. */
    fun requestIntent(c: Context): Intent? = request(c, RoleManager.ROLE_DIALER)

    /** The system consent screen for the call screening role; null when the role is not available. */
    fun requestScreeningIntent(c: Context): Intent? = request(c, RoleManager.ROLE_CALL_SCREENING)

    /** The system's default apps settings, where the phone app can be given back. */
    fun restoreIntent(): Intent = Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)

    /** Enables the "Phone" launcher entry while the dialer role is held and restores the manifest default otherwise. */
    fun syncLauncherAlias(c: Context) {
        runCatching {
            val pm = c.packageManager
            val component = ComponentName(c.packageName, PHONE_LAUNCHER)
            val wanted = if (isHeld(c)) {
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            } else {
                PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
            }
            if (pm.getComponentEnabledSetting(component) != wanted) {
                pm.setComponentEnabledSetting(component, wanted, PackageManager.DONT_KILL_APP)
            }
        }
    }

    private fun held(c: Context, role: String): Boolean = runCatching {
        val rm = c.getSystemService(RoleManager::class.java) ?: return false
        rm.isRoleAvailable(role) && rm.isRoleHeld(role)
    }.getOrDefault(false)

    private fun request(c: Context, role: String): Intent? = runCatching {
        val rm = c.getSystemService(RoleManager::class.java) ?: return null
        if (rm.isRoleAvailable(role)) rm.createRequestRoleIntent(role) else null
    }.getOrNull()
}

