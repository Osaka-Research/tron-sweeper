package com.harvest.tronsweep

import java.math.BigInteger
import java.security.MessageDigest

/** Base58 (Bitcoin/Tron alphabet) plus Base58Check (double-SHA256 checksum), as Tron addresses use. */
object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val INDEX = IntArray(128) { -1 }.also {
        for (i in ALPHABET.indices) it[ALPHABET[i].code] = i
    }

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""
        var zeros = 0
        while (zeros < input.size && input[zeros].toInt() == 0) zeros++

        var num = BigInteger(1, input)
        val base = BigInteger.valueOf(58)
        val sb = StringBuilder()
        while (num > BigInteger.ZERO) {
            val (div, rem) = num.divideAndRemainder(base)
            sb.append(ALPHABET[rem.toInt()])
            num = div
        }
        repeat(zeros) { sb.append(ALPHABET[0]) }
        return sb.reverse().toString()
    }

    fun decode(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        var num = BigInteger.ZERO
        val base = BigInteger.valueOf(58)
        for (c in input) {
            val digit = if (c.code < 128) INDEX[c.code] else -1
            require(digit >= 0) { "invalid base58 character: $c" }
            num = num.multiply(base).add(BigInteger.valueOf(digit.toLong()))
        }
        var bytes = num.toByteArray()
        if (bytes.size > 1 && bytes[0].toInt() == 0) bytes = bytes.copyOfRange(1, bytes.size)

        var zeros = 0
        while (zeros < input.length && input[zeros] == ALPHABET[0]) zeros++

        val out = ByteArray(zeros + bytes.size)
        System.arraycopy(bytes, 0, out, zeros, bytes.size)
        return out
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    fun encodeCheck(payload: ByteArray): String {
        val checksum = sha256(sha256(payload)).copyOfRange(0, 4)
        return encode(payload + checksum)
    }

    /** Decodes and verifies the checksum, returning the payload without it. */
    fun decodeCheck(input: String): ByteArray {
        val full = decode(input)
        require(full.size > 4) { "base58check string too short" }
        val payload = full.copyOfRange(0, full.size - 4)
        val checksum = full.copyOfRange(full.size - 4, full.size)
        val expected = sha256(sha256(payload)).copyOfRange(0, 4)
        require(checksum.contentEquals(expected)) { "base58check checksum mismatch" }
        return payload
    }
}
