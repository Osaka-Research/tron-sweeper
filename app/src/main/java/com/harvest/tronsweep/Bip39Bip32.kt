package com.harvest.tronsweep

import java.math.BigInteger
import java.text.Normalizer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * BIP39 mnemonic -> seed, and standard BIP32 secp256k1 derivation (supports
 * both hardened and non-hardened steps, unlike ed25519/SLIP-0010), for the
 * Tron BIP44 path m/44'/195'/0'/0/0 (195 = Tron's SLIP-44 coin type).
 *
 * Does NOT validate the mnemonic's BIP39 checksum (would need the full
 * 2048-word list embedded) - only word count. A typo'd mnemonic silently
 * derives a different wallet; check the shown derived address matches what
 * you expect before relying on it.
 */
object Bip39Bip32 {

    private const val PBKDF2_ITERATIONS = 2048
    private val VALID_WORD_COUNTS = setOf(12, 15, 18, 21, 24)
    const val TRON_DEFAULT_PATH = "m/44'/195'/0'/0/0"

    fun looksLikeMnemonic(input: String): Boolean {
        val words = input.trim().split(Regex("\\s+"))
        return words.size in VALID_WORD_COUNTS && words.all { it.isNotBlank() }
    }

    fun mnemonicToSeed(mnemonic: String, passphrase: String = ""): ByteArray {
        val normalizedMnemonic = Normalizer.normalize(mnemonic.trim(), Normalizer.Form.NFKD)
        val normalizedSalt = Normalizer.normalize("mnemonic$passphrase", Normalizer.Form.NFKD)
        return pbkdf2HmacSha512(normalizedMnemonic.toByteArray(Charsets.UTF_8), normalizedSalt.toByteArray(Charsets.UTF_8), PBKDF2_ITERATIONS, 64)
    }

    private fun pbkdf2HmacSha512(password: ByteArray, salt: ByteArray, iterations: Int, dkLenBytes: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(password, "HmacSHA512"))
        val hLen = mac.macLength
        val numBlocks = (dkLenBytes + hLen - 1) / hLen
        val out = ByteArray(numBlocks * hLen)
        for (blockIndex in 1..numBlocks) {
            mac.reset()
            mac.update(salt)
            mac.update(intToBigEndianBytes(blockIndex))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (i in 2..iterations) {
                mac.reset()
                u = mac.doFinal(u)
                for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte()
            }
            System.arraycopy(t, 0, out, (blockIndex - 1) * hLen, hLen)
        }
        return out.copyOf(dkLenBytes)
    }

    private fun intToBigEndianBytes(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun to32Bytes(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    private fun compressedPubKey(priv: BigInteger): ByteArray {
        val (x, y) = TronCrypto.publicKeyPoint(priv)
        val prefix: Byte = if (y.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix) + to32Bytes(x)
    }

    /** Returns the 32-byte private key derived along [path] (e.g. "m/44'/195'/0'/0/0"). */
    fun derivePath(seed: ByteArray, path: String): BigInteger {
        var mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec("Bitcoin seed".toByteArray(Charsets.UTF_8), "HmacSHA512"))
        var i = mac.doFinal(seed)
        var key = BigInteger(1, i.copyOfRange(0, 32))
        var chainCode = i.copyOfRange(32, 64)

        val segments = path.removePrefix("m/").split("/").filter { it.isNotBlank() }
        for (segment in segments) {
            val hardened = segment.endsWith("'") || segment.endsWith("h")
            val indexNum = segment.trimEnd('\'', 'h').toLong()
            val index = if (hardened) (indexNum or 0x80000000L) else indexNum

            val data = if (hardened) {
                byteArrayOf(0x00) + to32Bytes(key) + ser32(index)
            } else {
                compressedPubKey(key) + ser32(index)
            }

            mac = Mac.getInstance("HmacSHA512")
            mac.init(SecretKeySpec(chainCode, "HmacSHA512"))
            i = mac.doFinal(data)
            val il = BigInteger(1, i.copyOfRange(0, 32))
            chainCode = i.copyOfRange(32, 64)
            key = (il + key).mod(TronCrypto.N)
        }
        return key
    }

    private fun ser32(index: Long): ByteArray = byteArrayOf(
        (index ushr 24).toByte(), (index ushr 16).toByte(), (index ushr 8).toByte(), index.toByte()
    )
}
