package com.harvest.tronsweep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * Cross-checks the hand-rolled secp256k1/Keccak/Base58Check address derivation
 * against ~/.local/bin/tron-gen-address (same formulas, independently computed
 * in Python) for a fixed test private key - this moves real funds, so the
 * derivation and signing math get verified before trusting them, not after.
 */
class CryptoValidationTest {

    @Test
    fun addressDerivationMatchesKnownReference() {
        val privHex = "001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
        val expectedAddress = "TKrHnzR7FNgX1kGmBnq4grebzjyYCDwGqR"

        val kp = TronKeypair.parse(privHex)
        assertEquals(expectedAddress, kp.address)
    }

    @Test
    fun signAndRecoverRoundTrip() {
        val kp = TronKeypair.parse("001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd")
        val fakeTxId = MessageDigest.getInstance("SHA-256").digest("test transaction payload".toByteArray())

        // signHashToHex internally searches for the correct recovery id and throws
        // if it can't find one that recovers to this keypair's own public key -
        // so simply not throwing here already proves recovery math is self-consistent.
        val sigHex = kp.signHashToHex(fakeTxId)
        assertEquals(130, sigHex.length) // 65 bytes = r(32) + s(32) + v(1), hex-encoded
        assertTrue(sigHex.matches(Regex("[0-9a-f]{130}")))
    }

    @Test
    fun base58CheckRoundTrip() {
        val address = TronKeypair.parse("001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd").address
        val raw = Base58.decodeCheck(address)
        assertEquals(21, raw.size)
        assertEquals(0x41.toByte(), raw[0])
        assertEquals(address, Base58.encodeCheck(raw))
    }
}
