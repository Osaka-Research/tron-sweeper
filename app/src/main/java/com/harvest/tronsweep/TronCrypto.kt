package com.harvest.tronsweep

import org.bouncycastle.crypto.digests.KeccakDigest
import java.math.BigInteger

/**
 * secp256k1 field/point arithmetic ported directly from the already-working
 * ~/.local/bin/tron-gen-address script (same formulas, same constants) so
 * this matches a derivation that's already been exercised on this device,
 * rather than re-deriving the math from scratch.
 */
object TronCrypto {
    val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    val Gx = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    val Gy = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    val G = Pair(Gx, Gy)

    private fun inv(a: BigInteger, m: BigInteger): BigInteger = a.modPow(m - BigInteger.TWO, m)

    fun pointAdd(p1: Pair<BigInteger, BigInteger>?, p2: Pair<BigInteger, BigInteger>?): Pair<BigInteger, BigInteger>? {
        if (p1 == null) return p2
        if (p2 == null) return p1
        val (x1, y1) = p1
        val (x2, y2) = p2
        if (x1 == x2 && (y1 + y2).mod(P) == BigInteger.ZERO) return null
        val lam = if (p1 == p2) {
            (BigInteger.valueOf(3) * x1 * x1).mod(P) * inv((BigInteger.TWO * y1).mod(P), P) % P
        } else {
            (y2 - y1).mod(P) * inv((x2 - x1).mod(P), P) % P
        }
        val x3 = (lam * lam - x1 - x2).mod(P)
        val y3 = (lam * (x1 - x3) - y1).mod(P)
        return Pair(x3, y3)
    }

    fun scalarMult(k: BigInteger, point: Pair<BigInteger, BigInteger>): Pair<BigInteger, BigInteger> {
        var result: Pair<BigInteger, BigInteger>? = null
        var addend: Pair<BigInteger, BigInteger>? = point
        var kk = k
        while (kk > BigInteger.ZERO) {
            if (kk.testBit(0)) result = pointAdd(result, addend)
            addend = pointAdd(addend, addend)
            kk = kk.shiftRight(1)
        }
        return result!!
    }

    fun publicKeyPoint(privateKey: BigInteger): Pair<BigInteger, BigInteger> = scalarMult(privateKey, G)

    fun keccak256(data: ByteArray): ByteArray {
        val digest = KeccakDigest(256)
        digest.update(data, 0, data.size)
        val out = ByteArray(32)
        digest.doFinal(out, 0)
        return out
    }

    private fun bigIntTo32Bytes(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size) // drop sign byte
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    /** Tron mainnet base58check address from a public key point. */
    fun addressFromPublicKey(pub: Pair<BigInteger, BigInteger>): String {
        val pubBytes = bigIntTo32Bytes(pub.first) + bigIntTo32Bytes(pub.second)
        val hash = keccak256(pubBytes)
        val payload = byteArrayOf(0x41) + hash.copyOfRange(12, 32)
        return Base58.encodeCheck(payload)
    }

    /** The 21-byte raw address (0x41 prefix + 20-byte hash) Tron's REST API wants as "owner_address"/"to_address" hex. */
    fun rawAddressHex(base58Address: String): String {
        val payload = Base58.decodeCheck(base58Address)
        require(payload.size == 21 && payload[0] == 0x41.toByte()) { "not a valid Tron mainnet address" }
        return payload.joinToString("") { "%02x".format(it) }
    }
}
