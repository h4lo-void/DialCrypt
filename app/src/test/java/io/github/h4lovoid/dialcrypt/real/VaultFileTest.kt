package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.VaultFile
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class VaultFileTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val synced = mutableListOf<File>()

    private fun vault(dir: File = tmp.root) = File(dir, "vault.v2")

    private fun store(file: File) = VaultFile(file) { synced += it; true }

    @Test
    fun noFileReadsAsNull() {
        assertNull(store(vault()).read())
    }

    @Test
    fun writeReplacesAtomicallyAndSyncsTheDirectory() {
        val f = vault()
        val s = store(f)
        assertTrue(s.write(byteArrayOf(1, 2, 3)))
        assertArrayEquals(byteArrayOf(1, 2, 3), s.read())
        assertTrue(s.write(ByteArray(4096) { 9 }))
        assertArrayEquals(ByteArray(4096) { 9 }, s.read())
        assertEquals(listOf("vault.v2"), tmp.root.list()!!.toList())
        assertEquals(2, synced.size)
        assertEquals(tmp.root.absoluteFile, synced[0])
    }

    @Test
    fun writeCreatesTheDirectory() {
        val f = vault(File(tmp.root, "no_backup"))
        assertTrue(store(f).write(byteArrayOf(7)))
        assertArrayEquals(byteArrayOf(7), f.readBytes())
    }

    @Test
    fun failedWriteKeepsTheOldFile() {
        val f = vault()
        val s = store(f)
        assertTrue(s.write(byteArrayOf(1)))
        // A directory where the temporary file should go makes the write fail.
        assertTrue(File(tmp.root, "vault.v2.tmp").mkdir())
        assertFalse(s.write(byteArrayOf(2)))
        assertArrayEquals(byteArrayOf(1), s.read())
    }

    @Test
    fun failedDirectorySyncStillSucceedsOnceFileIsRenamed() {
        val f = vault()
        assertTrue(VaultFile(f) { false }.write(byteArrayOf(1)))
        assertArrayEquals(byteArrayOf(1), f.readBytes())
    }

    @Test
    fun overwriteKeepsLengthAndReplacesContent() {
        val f = vault()
        val s = store(f)
        val old = ByteArray(8192) { 0x41 }
        assertTrue(s.write(old))
        assertTrue(s.overwriteRandom())
        val now = s.read()!!
        assertEquals(old.size, now.size)
        assertFalse(now.contentEquals(old))
        assertTrue(s.overwrite(ByteArray(8192) { 5 }))
        assertArrayEquals(ByteArray(8192) { 5 }, s.read())
    }

    @Test
    fun destroyRemovesTheFile() {
        val f = vault()
        val s = store(f)
        assertTrue(s.write(ByteArray(100) { 1 }))
        assertTrue(s.destroy())
        assertFalse(f.exists())
        assertNull(s.read())
        assertTrue(s.destroy())
    }
}
