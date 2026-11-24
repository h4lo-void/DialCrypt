package io.github.h4lovoid.dialcrypt.core.real

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom

/**
 * The vault file (noBackupFilesDir/vault.v2). Writes go to a temporary file that is fsynced,
 * renamed over the vault in one step and followed by an fsync of the directory, so a crash
 * leaves either the old or the new file.
 */
internal class VaultFile(
    private val file: File,
    private val syncDirectory: (File) -> Boolean = ::fsyncDirectory,
) {
    private val tmp = File(file.path + ".tmp")
    private val dir: File? get() = file.absoluteFile.parentFile

    /** The file content, or null when there is no vault. Throws when it exists but cannot be read. */
    @Throws(IOException::class)
    fun read(): ByteArray? = if (file.exists()) file.readBytes() else null

    fun write(data: ByteArray): Boolean {
        val parent = dir ?: return false
        return try {
            if (!parent.isDirectory && !parent.mkdirs()) return false
            FileOutputStream(tmp).use { out ->
                out.write(data)
                out.fd.sync()
            }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE)
            // Once ATOMIC_MOVE completes, the new vault file is already in place; a directory
            // fsync error (seen on some SELinux/overlay setups) must not report the write failed.
            if (!syncDirectory(parent)) {
                runCatching { Log.w("AegisVault", "directory fsync failed after atomic rename") }
            }
            true
        } catch (e: IOException) {
            tmp.delete()
            false
        } catch (e: SecurityException) {
            tmp.delete()
            false
        }
    }

    /** Overwrites the existing file in place with [data] (same blocks where the file system allows) and fsyncs. */
    fun overwrite(data: ByteArray): Boolean = try {
        RandomAccessFile(file, "rw").use { f ->
            f.seek(0)
            f.write(data)
            f.setLength(data.size.toLong())
            f.fd.sync()
        }
        tmp.delete()
        true
    } catch (e: IOException) {
        false
    }

    /** Overwrites the file with random bytes of its own length; true when there is no file. */
    fun overwriteRandom(): Boolean {
        if (!file.exists()) return true
        val n = file.length()
        if (n > MAX_LEN) return false
        val noise = ByteArray(n.toInt())
        SecureRandom().nextBytes(noise)
        return overwrite(noise)
    }

    /** Random overwrite, then delete. */
    fun destroy(): Boolean {
        val overwritten = overwriteRandom()
        val deleted = !file.exists() || file.delete()
        tmp.delete()
        val parent = dir
        if (parent != null && !syncDirectory(parent)) {
            runCatching { Log.w("AegisVault", "directory fsync failed after destroy") }
        }
        return overwritten && deleted
    }

    private companion object {
        /** Far above any real vault (NativeBridge accepts at most 2 MiB). */
        const val MAX_LEN = 4L * 1024 * 1024
    }
}

/** fsync of a directory, so a rename inside it is durable. To be confirmed on device: allowed on noBackupFilesDir under the app's SELinux domain. */
internal fun fsyncDirectory(dir: File): Boolean = try {
    val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
    try {
        Os.fsync(fd)
        true
    } finally {
        Os.close(fd)
    }
} catch (_: ErrnoException) {
    false
} catch (_: Exception) {
    false
}
