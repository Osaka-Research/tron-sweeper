package com.harvest.tronsweep

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger

class TronKeypair private constructor(val privateKey: BigInteger) {

    private val publicPoint: Pair<BigInteger, BigInteger> = TronCrypto.publicKeyPoint(privateKey)
    val address: String get() = TronCrypto.addressFromPublicKey(publicPoint)
    val rawAddressHex: String get() = TronCrypto.rawAddressHex(address)

    /** Signs a 32-byte hash (Tron's txID), returns the 65-byte r||s||v signature Tron expects, hex-encoded. */
    fun signHashToHex(hash32: ByteArray): String {
        val curve = SECNamedCurves.getByName("secp256k1")
        val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h)
        val privParams = ECPrivateKeyParameters(privateKey, domain)

        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, privParams)
        val components = signer.generateSignature(hash32)
        var r = components[0]
        var s = components[1]

        // low-S normalization (Tron/Ethereum convention)
        val halfN = TronCrypto.N.shiftRight(1)
        if (s > halfN) s = TronCrypto.N.subtract(s)

        val v = findRecoveryId(hash32, r, s, curve.curve.decodePoint(encodePubKeyUncompressed()))
        val sigBytes = to32Bytes(r) + to32Bytes(s) + byteArrayOf(v.toByte())
        return sigBytes.joinToString("") { "%02x".format(it) }
    }

    private fun encodePubKeyUncompressed(): ByteArray =
        byteArrayOf(0x04) + to32Bytes(publicPoint.first) + to32Bytes(publicPoint.second)

    private fun findRecoveryId(hash: ByteArray, r: BigInteger, s: BigInteger, expectedPub: ECPoint): Int {
        for (recId in 0..1) {
            val recovered = recoverPubKey(hash, r, s, recId) ?: continue
            if (recovered.equals(expectedPub)) return recId
        }
        throw IllegalStateException("could not determine ECDSA recovery id - signature/pubkey mismatch")
    }

    private fun recoverPubKey(hash: ByteArray, r: BigInteger, s: BigInteger, recId: Int): ECPoint? {
        val curveParams = SECNamedCurves.getByName("secp256k1")
        val curve = curveParams.curve
        val n = TronCrypto.N

        val x = r
        if (x >= curve.field.characteristic) return null
        val rPointCandidate = try {
            curve.decodePoint(byteArrayOf(if (recId and 1 == 0) 0x02 else 0x03) + to32Bytes(x))
        } catch (e: Exception) {
            return null
        }
        if (!rPointCandidate.multiply(n).isInfinity) return null

        val e = BigInteger(1, hash)
        val eInv = n.subtract(e.mod(n))
        val rInv = r.modInverse(n)
        val srInv = rInv.multiply(s).mod(n)
        val eInvrInv = rInv.multiply(eInv).mod(n)

        val gPoint = curveParams.g
        return gPoint.multiply(eInvrInv).add(rPointCandidate.multiply(srInv)).normalize()
    }

    private fun to32Bytes(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    companion object {
        fun fromPrivateKey(priv: BigInteger): TronKeypair = TronKeypair(priv)

        @Throws(IllegalArgumentException::class)
        fun parse(input: String): TronKeypair {
            val trimmed = input.trim()
            if (Bip39Bip32.looksLikeMnemonic(trimmed)) {
                val seed = Bip39Bip32.mnemonicToSeed(trimmed)
                val priv = Bip39Bip32.derivePath(seed, Bip39Bip32.TRON_DEFAULT_PATH)
                return TronKeypair(priv)
            }
            val hex = trimmed.removePrefix("0x")
            require(hex.length == 64 && hex.matches(Regex("[0-9a-fA-F]+"))) {
                "secret key must be 64 hex chars (or a mnemonic phrase), got ${hex.length} chars"
            }
            return TronKeypair(BigInteger(hex, 16))
        }
    }
}
