package com.airdrop.p2p

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement

class AirDropSecurityTest {

    @Test
    fun ecdhP256SharedSecretDerivationMatchesBetweenPeers() {
        // Peer A (Android) and Peer B (Mac) using AirDropNode production companion methods
        val pairA = AirDropNode.generateEphemeralEcdhKeyPair()
        val pairB = AirDropNode.generateEphemeralEcdhKeyPair()

        val sessionKeyA = AirDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)
        val sessionKeyB = AirDropNode.deriveSessionKey(pairB.privateKey, pairA.publicKey.encoded)

        assertEquals(32, sessionKeyA.size)
        assertEquals(32, sessionKeyB.size)
        assertArrayEquals("Session keys derived from both sides must be bit-for-bit identical", sessionKeyA, sessionKeyB)
    }

    @Test
    fun distinctKeyPairsDeriveUniqueSessionKeys() {
        val pairA1 = AirDropNode.generateEphemeralEcdhKeyPair()
        val pairB1 = AirDropNode.generateEphemeralEcdhKeyPair()
        val pairA2 = AirDropNode.generateEphemeralEcdhKeyPair()

        val key1 = AirDropNode.deriveSessionKey(pairA1.privateKey, pairB1.publicKey.encoded)
        val key2 = AirDropNode.deriveSessionKey(pairA2.privateKey, pairB1.publicKey.encoded)

        assertFalse("Different ephemeral private keys must derive completely different session keys", key1.contentEquals(key2))
    }

    @Test
    fun wifiDirectCredentialsAes256GcmRoundTrip() {
        val pairA = AirDropNode.generateEphemeralEcdhKeyPair()
        val pairB = AirDropNode.generateEphemeralEcdhKeyPair()
        val sessionKey = AirDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)

        val ssid = "DIRECT-aB-AirDrop-Test-5G"
        val pass = "SuperSecretP2pPassphrase99!"
        val plainText = "$ssid\t$pass".toByteArray(StandardCharsets.UTF_8)

        val encryptedPacket = AirDropNode.encryptAesGcm(plainText, sessionKey)
        assertTrue("Ciphertext must include 12-byte IV + payload + 16-byte tag", encryptedPacket.size >= 28 + plainText.size)

        val decryptedBytes = AirDropNode.decryptAesGcm(encryptedPacket, sessionKey)
        assertArrayEquals(plainText, decryptedBytes)

        val decryptedStr = String(decryptedBytes, StandardCharsets.UTF_8)
        val parts = decryptedStr.split('\t')
        assertEquals(ssid, parts[0])
        assertEquals(pass, parts[1])
    }

    @Test
    fun aes256GcmRejectsTamperedCiphertext() {
        val pairA = AirDropNode.generateEphemeralEcdhKeyPair()
        val pairB = AirDropNode.generateEphemeralEcdhKeyPair()
        val sessionKey = AirDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)

        val plainText = "DIRECT-xy\tsecret123".toByteArray(StandardCharsets.UTF_8)
        val encryptedPacket = AirDropNode.encryptAesGcm(plainText, sessionKey)

        // Tamper with one bit in the ciphertext / auth tag
        encryptedPacket[15] = (encryptedPacket[15].toInt() xor 0x01).toByte()

        try {
            AirDropNode.decryptAesGcm(encryptedPacket, sessionKey)
            fail("Decryption of tampered ciphertext must throw an AEAD authentication exception")
        } catch (_: javax.crypto.AEADBadTagException) {
            // Expected
        } catch (_: java.security.GeneralSecurityException) {
            // Expected
        }
    }

    @Test
    fun aes256GcmRejectsShortPackets() {
        val key = ByteArray(32) { 0x42 }
        try {
            AirDropNode.decryptAesGcm(ByteArray(27), key)
            fail("Packets shorter than 28 bytes (12 IV + 16 Tag) must be rejected")
        } catch (_: java.io.IOException) {
            // Expected
        }
    }

    @Test
    fun malformedOrCorruptedPeerEcPublicKeyRejection() {
        val pairA = AirDropNode.generateEphemeralEcdhKeyPair()
        val garbageBytes = byteArrayOf(0x30, 0x10, 0x01, 0x02, 0x03, 0x04)

        try {
            AirDropNode.deriveSessionKey(pairA.privateKey, garbageBytes)
            fail("Deriving session key with invalid DER public key must throw InvalidKeySpecException")
        } catch (_: InvalidKeySpecException) {
            // Expected
        } catch (_: java.security.GeneralSecurityException) {
            // Expected
        }
    }

    @Test
    fun tlsCertificateFingerprintVerification() {
        val fakeDerCert = "fake-der-certificate-payload-bytes".toByteArray(StandardCharsets.UTF_8)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(fakeDerCert)
        val actualFp = digest.joinToString("") { "%02x".format(it) }.lowercase()

        // Test colon-delimited and dash-delimited formatting tolerance
        val colonFp = digest.joinToString(":") { "%02x".format(it) }.uppercase()
        val dashFp = digest.joinToString("-") { "%02x".format(it) }

        val normColon = colonFp.replace(":", "").replace("-", "").trim().lowercase()
        val normDash = dashFp.replace(":", "").replace("-", "").trim().lowercase()

        assertEquals(actualFp, normColon)
        assertEquals(actualFp, normDash)

        // Test mismatch detection
        val wrongFp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val isMismatch = !actualFp.equals(wrongFp, ignoreCase = true)
        assertTrue(isMismatch)
    }

    @Test
    fun crossLanguageTestVectorDerivation() {
        // Verify deterministic P-256 ECDH derivation matching the Swift test vector
        // Using fixed scalar s = 33..64 and peer public key PUB1_DER from Swift
        val p2Data = ByteArray(32) { (it + 33).toByte() }
        val s = BigInteger(1, p2Data)

        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)
        val privSpec = ECPrivateKeySpec(s, ecSpec)
        val priv2 = KeyFactory.getInstance("EC").generatePrivate(privSpec)

        val pub1Der = Base64.getDecoder().decode(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUVw9brnjlrkE0/7Kf1T9zQzB6Ze/N13KUVrQpsO0A19FNr46UPMY+/mlR1kCoiFQK+8NV+CMU7LMClbxfZ+TVA=="
        )
        val pub1 = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pub1Der))

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv2)
        ka.doPhase(pub1, true)
        val secret = ka.generateSecret()

        val md = MessageDigest.getInstance("SHA-256")
        md.update(secret)
        md.update("AirDropP2P-v2-SessionKey".toByteArray(StandardCharsets.UTF_8))
        val sessionKey = md.digest()

        val sessionKeyB64 = Base64.getEncoder().encodeToString(sessionKey)
        // Must match exact Swift output: V0EbP7kiAUG3sFkBivaYBnjQvunQpA8jTTPbNreDgJ0=
        assertEquals("V0EbP7kiAUG3sFkBivaYBnjQvunQpA8jTTPbNreDgJ0=", sessionKeyB64)
    }

    @Test
    fun w2p2PayloadParsingHandlesVersionedAndUnversioned() {
        // Helper to test the parsing logic added to AirDropNode
        fun parseW2P2Line(line: String): Pair<String, String?> {
            val rawParts = line.trimStart('\t').split('\t')
            val parts = rawParts.filter { it.isNotEmpty() }
            return when {
                parts.size >= 3 && (parts[0] == "2" || parts[0] == "1") -> parts[1] to parts[2]
                parts.size == 2 && (parts[0] == "2" || parts[0] == "1") -> parts[1] to null
                parts.size >= 2 -> parts[0] to parts[1]
                parts.size == 1 -> parts[0] to null
                else -> "" to null
            }
        }

        // 1. Version 2 format: "\t2\t<macPubB64>\t<fingerprint>"
        val v2Res = parseW2P2Line("\t2\tPUB_KEY_B64\tFINGERPRINT_HEX")
        assertEquals("PUB_KEY_B64", v2Res.first)
        assertEquals("FINGERPRINT_HEX", v2Res.second)

        // 2. Unversioned format: "\t<macPubB64>\t<fingerprint>"
        val unvRes = parseW2P2Line("\tPUB_KEY_B64\tFINGERPRINT_HEX")
        assertEquals("PUB_KEY_B64", unvRes.first)
        assertEquals("FINGERPRINT_HEX", unvRes.second)

        // 3. Version without fingerprint: "\t2\t<macPubB64>"
        val noFpRes = parseW2P2Line("\t2\tPUB_KEY_B64")
        assertEquals("PUB_KEY_B64", noFpRes.first)
        assertNull(noFpRes.second)

        // 4. Empty/whitespace string
        val emptyRes = parseW2P2Line("")
        assertEquals("", emptyRes.first)
        assertNull(emptyRes.second)
    }

    @Test
    fun bufferedStreamDataInputStreamDoesNotStallOnW2P2Line() {
        // Simulate sending "W2P2\tPUB_B64\tFP_HEX\n" into an L2CAP channel
        val testWireData = "W2P2\tMEYCIQ...\tdeadbeef1234\n".toByteArray(StandardCharsets.UTF_8)
        val inStream = ByteArrayInputStream(testWireData)
        val dis = DataInputStream(BufferedInputStream(inStream, 65536))

        // Read 4 bytes magic
        val magic = ByteArray(4)
        dis.readFully(magic)
        assertEquals("W2P2", String(magic, StandardCharsets.US_ASCII))

        // Ensure reading from dis (rather than bypassing to raw inStream) reads the remainder correctly
        val buf = ByteArrayOutputStream()
        while (true) {
            val b = dis.read()
            if (b == -1 || b == '\n'.code) break
            if (b != '\r'.code) buf.write(b)
        }
        val remainder = buf.toString(StandardCharsets.ISO_8859_1.name())
        assertEquals("\tMEYCIQ...\tdeadbeef1234", remainder)
    }

    @Test
    fun encryptedBleArchiveLengthCapRejectsOversizedBuffers() {
        // Valid bounds: Encrypted BLE (ADRE) with 30 MB is allowed
        assertTrue(AirDropNode.isValidBleFrameBounds(512, 30_000_000, isEncryptedBle = true))

        // Rejection: Encrypted BLE (ADRE) with 30 MB + 1 byte must be rejected to prevent JVM OOM
        assertFalse(AirDropNode.isValidBleFrameBounds(512, 30_000_001, isEncryptedBle = true))

        // Rejection: Encrypted BLE (ADRE) with 1.8 GB must be rejected
        assertFalse(AirDropNode.isValidBleFrameBounds(512, 1_800_000_000, isEncryptedBle = true))

        // Boundary tests for metaLen
        assertFalse(AirDropNode.isValidBleFrameBounds(0, 1024, isEncryptedBle = true))
        assertFalse(AirDropNode.isValidBleFrameBounds(-1, 1024, isEncryptedBle = true))
        assertTrue(AirDropNode.isValidBleFrameBounds(AirDropNode.MAX_BLE_META_BYTES, 1024, isEncryptedBle = true))
        assertFalse(AirDropNode.isValidBleFrameBounds(AirDropNode.MAX_BLE_META_BYTES + 1, 1024, isEncryptedBle = true))

        // Negative archive length rejection
        assertFalse(AirDropNode.isValidBleFrameBounds(512, -1, isEncryptedBle = true))

        // Unencrypted BLE (ADRP) streaming bounds
        assertTrue(AirDropNode.isValidBleFrameBounds(512, 50_000_000, isEncryptedBle = false))
        assertTrue(AirDropNode.isValidBleFrameBounds(512, 1_800_000_000, isEncryptedBle = false))
        assertFalse(AirDropNode.isValidBleFrameBounds(512, 1_800_000_001, isEncryptedBle = false))
    }

    @Test
    fun multiFileStagingCalculatesAggregateSize() {
        val testSizes = listOf(4_500_000L, 3_200_000L, 45_000_000L)
        val aggregateBytes = AirDropNode.calculateAggregateStagedBytes(testSizes)
        assertEquals(52_700_000L, aggregateBytes)

        // Robustness: Negative sizes from non-seekable streams (-1L) are coerced to 0L without skewing total
        val mixedSizes = listOf(10_000_000L, -1L, 5_000_000L)
        assertEquals(15_000_000L, AirDropNode.calculateAggregateStagedBytes(mixedSizes))

        // Multi-file label formatting
        assertEquals("photo.jpg", AirDropNode.formatMultiFileDisplayLabel("photo.jpg", 1))
        assertEquals("photo.jpg (+2 more)", AirDropNode.formatMultiFileDisplayLabel("photo.jpg", 3))
    }
}
