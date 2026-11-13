package io.github.jakharamit44.glidedrop

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
import java.io.File
import java.math.BigInteger
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

class GlideDropSecurityTest {

    private fun testDecryptAesGcm(packet: ByteArray, sessionKeyBytes: ByteArray): ByteArray {
        if (packet.size < 28) throw java.io.IOException("Encrypted frame too short")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKeyBytes, "AES"), GCMParameterSpec(128, packet, 0, 12))
        return cipher.doFinal(packet, 12, packet.size - 12)
    }

    @Test
    fun ecdhP256SharedSecretDerivationMatchesBetweenPeers() {
        // Peer A (Android) and Peer B (Mac) using GlideDropNode production companion methods
        val pairA = GlideDropNode.generateEphemeralEcdhKeyPair()
        val pairB = GlideDropNode.generateEphemeralEcdhKeyPair()

        val sessionKeyA = GlideDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)
        val sessionKeyB = GlideDropNode.deriveSessionKey(pairB.privateKey, pairA.publicKey.encoded)

        assertEquals(32, sessionKeyA.size)
        assertEquals(32, sessionKeyB.size)
        assertArrayEquals("Session keys derived from both sides must be bit-for-bit identical", sessionKeyA, sessionKeyB)
    }

    @Test
    fun distinctKeyPairsDeriveUniqueSessionKeys() {
        val pairA1 = GlideDropNode.generateEphemeralEcdhKeyPair()
        val pairB1 = GlideDropNode.generateEphemeralEcdhKeyPair()
        val pairA2 = GlideDropNode.generateEphemeralEcdhKeyPair()

        val key1 = GlideDropNode.deriveSessionKey(pairA1.privateKey, pairB1.publicKey.encoded)
        val key2 = GlideDropNode.deriveSessionKey(pairA2.privateKey, pairB1.publicKey.encoded)

        assertFalse("Different ephemeral private keys must derive completely different session keys", key1.contentEquals(key2))
    }

    @Test
    fun wifiDirectCredentialsAes256GcmRoundTrip() {
        val pairA = GlideDropNode.generateEphemeralEcdhKeyPair()
        val pairB = GlideDropNode.generateEphemeralEcdhKeyPair()
        val sessionKey = GlideDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)

        val ssid = "DIRECT-aB-GlideDrop-Test-5G"
        val pass = "SuperSecretP2pPassphrase99!"
        val plainText = "$ssid\t$pass".toByteArray(StandardCharsets.UTF_8)

        val encryptedPacket = GlideDropNode.encryptAesGcm(plainText, sessionKey)
        assertTrue("Ciphertext must include 12-byte IV + payload + 16-byte tag", encryptedPacket.size >= 28 + plainText.size)

        val decryptedBytes = testDecryptAesGcm(encryptedPacket, sessionKey)
        assertArrayEquals(plainText, decryptedBytes)

        val decryptedStr = String(decryptedBytes, StandardCharsets.UTF_8)
        val parts = decryptedStr.split('\t')
        assertEquals(ssid, parts[0])
        assertEquals(pass, parts[1])
    }

    @Test
    fun aes256GcmRejectsTamperedCiphertext() {
        val pairA = GlideDropNode.generateEphemeralEcdhKeyPair()
        val pairB = GlideDropNode.generateEphemeralEcdhKeyPair()
        val sessionKey = GlideDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)

        val plainText = "DIRECT-xy\tsecret123".toByteArray(StandardCharsets.UTF_8)
        val encryptedPacket = GlideDropNode.encryptAesGcm(plainText, sessionKey)

        // Tamper with one bit in the ciphertext / auth tag
        encryptedPacket[15] = (encryptedPacket[15].toInt() xor 0x01).toByte()

        try {
            testDecryptAesGcm(encryptedPacket, sessionKey)
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
            testDecryptAesGcm(ByteArray(27), key)
            fail("Packets shorter than 28 bytes (12 IV + 16 Tag) must be rejected")
        } catch (_: java.io.IOException) {
            // Expected
        }
    }

    @Test
    fun malformedOrCorruptedPeerEcPublicKeyRejection() {
        val pairA = GlideDropNode.generateEphemeralEcdhKeyPair()
        val garbageBytes = byteArrayOf(0x30, 0x10, 0x01, 0x02, 0x03, 0x04)

        try {
            GlideDropNode.deriveSessionKey(pairA.privateKey, garbageBytes)
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
        md.update("GlideDrop-v2-SessionKey".toByteArray(StandardCharsets.UTF_8))
        val sessionKey = md.digest()

        val sessionKeyB64 = Base64.getEncoder().encodeToString(sessionKey)
        // Must match exact Swift output: yC4CQspFyUEHQ8fiY9BhEhGOrB0F1UGUUtwaSF3WA/4=
        assertEquals("yC4CQspFyUEHQ8fiY9BhEhGOrB0F1UGUUtwaSF3WA/4=", sessionKeyB64)
    }

    @Test
    fun w2p2PayloadParsingHandlesVersionedAndUnversioned() {
        // 1. Version 2 format: "\t2\t<macPubB64>\t<fingerprint>"
        val v2Res = GlideDropNode.parseW2P2Line("\t2\tPUB_KEY_B64\tFINGERPRINT_HEX")
        assertEquals("PUB_KEY_B64", v2Res.first)
        assertEquals("FINGERPRINT_HEX", v2Res.second)

        // 2. Unversioned format: "\t<macPubB64>\t<fingerprint>"
        val unvRes = GlideDropNode.parseW2P2Line("\tPUB_KEY_B64\tFINGERPRINT_HEX")
        assertEquals("PUB_KEY_B64", unvRes.first)
        assertEquals("FINGERPRINT_HEX", unvRes.second)

        // 3. Version without fingerprint: "\t2\t<macPubB64>"
        val noFpRes = GlideDropNode.parseW2P2Line("\t2\tPUB_KEY_B64")
        assertEquals("PUB_KEY_B64", noFpRes.first)
        assertNull(noFpRes.second)

        // 4. Empty/whitespace string
        val emptyRes = GlideDropNode.parseW2P2Line("")
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
        assertTrue(GlideDropNode.isValidBleFrameBounds(512, 30_000_000, isEncryptedBle = true))

        // Rejection: Encrypted BLE (ADRE) with 30 MB + 1 byte must be rejected to prevent JVM OOM
        assertFalse(GlideDropNode.isValidBleFrameBounds(512, 30_000_001, isEncryptedBle = true))

        // Rejection: Encrypted BLE (ADRE) with 1.8 GB must be rejected
        assertFalse(GlideDropNode.isValidBleFrameBounds(512, 1_800_000_000, isEncryptedBle = true))

        // Boundary tests for metaLen
        assertFalse(GlideDropNode.isValidBleFrameBounds(0, 1024, isEncryptedBle = true))
        assertFalse(GlideDropNode.isValidBleFrameBounds(-1, 1024, isEncryptedBle = true))
        assertTrue(GlideDropNode.isValidBleFrameBounds(GlideDropNode.MAX_BLE_META_BYTES, 1024, isEncryptedBle = true))
        assertFalse(GlideDropNode.isValidBleFrameBounds(GlideDropNode.MAX_BLE_META_BYTES + 1, 1024, isEncryptedBle = true))

        // Negative archive length rejection
        assertFalse(GlideDropNode.isValidBleFrameBounds(512, -1, isEncryptedBle = true))

        // Unencrypted BLE (ADRP) streaming bounds
        assertTrue(GlideDropNode.isValidBleFrameBounds(512, 50_000_000, isEncryptedBle = false))
        assertTrue(GlideDropNode.isValidBleFrameBounds(512, 1_800_000_000, isEncryptedBle = false))
        assertFalse(GlideDropNode.isValidBleFrameBounds(512, 1_800_000_001, isEncryptedBle = false))
    }

    @Test
    fun multiFileStagingCalculatesAggregateSize() {
        val testSizes = listOf(4_500_000L, 3_200_000L, 45_000_000L)
        val aggregateBytes = GlideDropNode.calculateAggregateStagedBytes(testSizes)
        assertEquals(52_700_000L, aggregateBytes)

        // Robustness: Negative sizes from non-seekable streams (-1L) are coerced to 0L without skewing total
        val mixedSizes = listOf(10_000_000L, -1L, 5_000_000L)
        assertEquals(15_000_000L, GlideDropNode.calculateAggregateStagedBytes(mixedSizes))

        // Multi-file label formatting
        assertEquals("photo.jpg", GlideDropNode.formatMultiFileDisplayLabel("photo.jpg", 1))
        assertEquals("photo.jpg (+2 more)", GlideDropNode.formatMultiFileDisplayLabel("photo.jpg", 3))
    }

    private fun generateTestKeyStore(alias: String, commonName: String): KeyStore {
        val tmpDir = Files.createTempDirectory("glidedrop-tls-test")
        try {
            val ksFile = tmpDir.resolve("$alias.p12").toFile()
            val keytoolPath = File(System.getProperty("java.home"), "bin/keytool").absolutePath
            val passStr = "test-keystore-pass"
            val proc = ProcessBuilder(
                keytoolPath,
                "-genkeypair",
                "-alias", alias,
                "-keyalg", "EC",
                "-groupname", "secp256r1",
                "-sigalg", "SHA256withECDSA",
                "-dname", "CN=$commonName",
                "-validity", "365",
                "-storetype", "PKCS12",
                "-keystore", ksFile.absolutePath,
                "-storepass", passStr,
                "-keypass", passStr
            )
                .redirectErrorStream(true)
                .start()
            val output = proc.inputStream.bufferedReader().readText()
            val rc = proc.waitFor()
            require(rc == 0) { "keytool failed (exit $rc): $output" }
            return KeyStore.getInstance("PKCS12").apply {
                ksFile.inputStream().use { load(it, passStr.toCharArray()) }
            }
        } finally {
            tmpDir.toFile().deleteRecursively()
        }
    }

    private fun buildServerContextFromKeyStore(ks: KeyStore): SSLContext {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(ks, "test-keystore-pass".toCharArray())
        }
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, null, null)
        }
    }

    @Test
    fun pinnedTlsTrustManagerValidatesExactCertificateAndRejectsMismatch() {
        val ksA = generateTestKeyStore("peerA", "glidedrop-peer-a")
        val ksB = generateTestKeyStore("peerB", "glidedrop-peer-b")
        val certA = ksA.getCertificate("peerA") as X509Certificate
        val certB = ksB.getCertificate("peerB") as X509Certificate

        val fpA = GlideDropNode.sha256FingerprintHex(certA)
        val colonFpA = fpA.chunked(2).joinToString(":").uppercase()
        val dashFpA = fpA.chunked(2).joinToString("-")

        // Matching fingerprint (raw, colon-delimited uppercase, dash-delimited) must succeed
        GlideDropNode.PinnedTlsTrustManager(fpA).checkServerTrusted(arrayOf(certA), "ECDHE_ECDSA")
        GlideDropNode.PinnedTlsTrustManager(colonFpA).checkServerTrusted(arrayOf(certA), "ECDHE_ECDSA")
        GlideDropNode.PinnedTlsTrustManager("  $dashFpA  ").checkServerTrusted(arrayOf(certA), "ECDHE_ECDSA")

        val tm = GlideDropNode.PinnedTlsTrustManager(fpA)

        // Mismatched certificate must throw CertificateException
        try {
            tm.checkServerTrusted(arrayOf(certB), "ECDHE_ECDSA")
            fail("Mismatched peer certificate must throw CertificateException")
        } catch (_: CertificateException) {
            // Expected
        }

        // Multi-cert chain where attacker leaf certB is followed by pinned certA must still reject leaf
        try {
            tm.checkServerTrusted(arrayOf(certB, certA), "ECDHE_ECDSA")
            fail("Multi-cert chain with untrusted leaf must throw CertificateException")
        } catch (_: CertificateException) {
            // Expected
        }

        // Empty or null chain must throw CertificateException
        try {
            tm.checkServerTrusted(emptyArray<X509Certificate>(), "ECDHE_ECDSA")
            fail("Empty certificate chain must throw CertificateException")
        } catch (_: CertificateException) {
            // Expected
        }
        try {
            tm.checkServerTrusted(null, "ECDHE_ECDSA")
            fail("Null certificate chain must throw CertificateException")
        } catch (_: CertificateException) {
            // Expected
        }

        // Client cert auth on server-pinning TrustManager must reject with CertificateException
        try {
            tm.checkClientTrusted(arrayOf(certA), "ECDHE_ECDSA")
            fail("checkClientTrusted must throw CertificateException")
        } catch (_: CertificateException) {
            // Expected
        }

        // Invalid or empty pin strings must fail closed at construction
        for (badPin in listOf("", "   ", "deadbeef", "zz".repeat(32), "a".repeat(63), "a".repeat(65))) {
            assertFalse("Expected isValidSha256Fingerprint to reject '$badPin'", GlideDropNode.isValidSha256Fingerprint(badPin))
            try {
                GlideDropNode.PinnedTlsTrustManager(badPin)
                fail("Invalid fingerprint '$badPin' must be rejected")
            } catch (_: IllegalArgumentException) {
                // Expected
            }
        }
        assertFalse(GlideDropNode.isValidSha256Fingerprint(null))
        assertTrue(GlideDropNode.isValidSha256Fingerprint(fpA))
        assertTrue(GlideDropNode.isValidSha256Fingerprint(colonFpA))
        assertTrue(GlideDropNode.isValidSha256Fingerprint("  $dashFpA  "))
    }

    @Test
    fun pinnedClientSslContextEnforcesHandshakePinningOverLoopbackTls() {
        val ksA = generateTestKeyStore("srvA", "glidedrop-srv-a")
        val ksB = generateTestKeyStore("srvB", "glidedrop-srv-b")
        val certA = ksA.getCertificate("srvA") as X509Certificate
        val certB = ksB.getCertificate("srvB") as X509Certificate
        val fpA = GlideDropNode.sha256FingerprintHex(certA)
        val fpB = GlideDropNode.sha256FingerprintHex(certB)

        val serverCtx = buildServerContextFromKeyStore(ksA)
        val srv = (serverCtx.serverSocketFactory.createServerSocket(0, 8, InetAddress.getByName("127.0.0.1")) as SSLServerSocket).apply {
            soTimeout = 5_000
        }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val serverFuture = executor.submit {
                repeat(4) {
                    try {
                        (srv.accept() as SSLSocket).use { client ->
                            client.soTimeout = 5_000
                            client.startHandshake()
                            client.outputStream.write("OK".toByteArray(StandardCharsets.US_ASCII))
                            client.outputStream.flush()
                        }
                    } catch (_: Throwable) {
                        // Expected on rejected client handshakes
                    }
                }
            }

            // 1. Pinned fingerprint matching server cert A must succeed (leaves endpointIdentificationAlgorithm unset for self-signed P2P cert)
            val matchingCtx = GlideDropNode.buildPinnedClientSslContext(fpA)
            (matchingCtx.socketFactory.createSocket("127.0.0.1", srv.localPort) as SSLSocket).use { tls ->
                tls.soTimeout = 5_000
                GlideDropNode.configureClientTlsSocket(tls, isPinned = true)
                assertNull(tls.sslParameters.endpointIdentificationAlgorithm)
                tls.startHandshake()
                val buf = ByteArray(2)
                assertEquals(2, tls.inputStream.read(buf))
                assertEquals("OK", String(buf, StandardCharsets.US_ASCII))
            }

            // 2. Mismatched fingerprint (simulating MitM cert) must abort TLS handshake
            val wrongPinCtx = GlideDropNode.buildPinnedClientSslContext(fpB)
            (wrongPinCtx.socketFactory.createSocket("127.0.0.1", srv.localPort) as SSLSocket).use { tls ->
                tls.soTimeout = 5_000
                GlideDropNode.configureClientTlsSocket(tls, isPinned = true)
                try {
                    tls.startHandshake()
                    fail("TLS handshake with mismatched pinned fingerprint must fail")
                } catch (_: SSLHandshakeException) {
                    // Expected
                } catch (_: CertificateException) {
                    // Expected
                }
            }

            // 3. Default platform SSLContext without pin must configure HTTPS endpoint identification and reject untrusted self-signed cert
            val defaultCtx = GlideDropNode.buildDefaultClientSslContext()
            (defaultCtx.socketFactory.createSocket("127.0.0.1", srv.localPort) as SSLSocket).use { tls ->
                tls.soTimeout = 5_000
                GlideDropNode.configureClientTlsSocket(tls, isPinned = false)
                assertEquals("HTTPS", tls.sslParameters.endpointIdentificationAlgorithm)
                try {
                    tls.startHandshake()
                    fail("Default TrustManager must reject untrusted self-signed server certificate")
                } catch (_: SSLHandshakeException) {
                    // Expected
                } catch (_: CertificateException) {
                    // Expected
                }
            }

            // 4. Even if server cert is in trust store, configureClientTlsSocket(isPinned = false) enforces HTTPS hostname/IP verification
            val tmfA = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ksA) }
            val trustedCtxA = SSLContext.getInstance("TLS").apply { init(null, tmfA.trustManagers, null) }
            (trustedCtxA.socketFactory.createSocket("127.0.0.1", srv.localPort) as SSLSocket).use { tls ->
                tls.soTimeout = 5_000
                GlideDropNode.configureClientTlsSocket(tls, isPinned = false)
                assertEquals("HTTPS", tls.sslParameters.endpointIdentificationAlgorithm)
                try {
                    tls.startHandshake()
                    fail("HTTPS endpoint identification must reject CN=glidedrop-srv-a for 127.0.0.1")
                } catch (_: javax.net.ssl.SSLException) {
                    // Expected
                } catch (_: CertificateException) {
                    // Expected
                }
            }

            serverFuture.get(5, TimeUnit.SECONDS)
        } finally {
            runCatching { srv.close() }
            executor.shutdownNow()
        }
    }

    @Test
    fun ephemeralBleFrameKeyAndBearerTokenDomainSeparation() {
        val pairA = GlideDropNode.generateEphemeralEcdhKeyPair()
        val pairB = GlideDropNode.generateEphemeralEcdhKeyPair()

        val sessionKeyA = GlideDropNode.deriveSessionKey(pairA.privateKey, pairB.publicKey.encoded)
        val bleFrameKeyA = GlideDropNode.deriveBleFrameKey(pairA.privateKey, pairB.publicKey.encoded)
        val bleFrameKeyB = GlideDropNode.deriveBleFrameKey(pairB.privateKey, pairA.publicKey.encoded)
        val tokenA = GlideDropNode.deriveSessionToken(pairA.privateKey, pairB.publicKey.encoded)
        val tokenB = GlideDropNode.deriveSessionToken(pairB.privateKey, pairA.publicKey.encoded)
        val (comboKey, comboToken) = GlideDropNode.deriveSessionKeyAndToken(pairA.privateKey, pairB.publicKey.encoded)

        assertEquals(32, bleFrameKeyA.size)
        assertArrayEquals("Both peers must derive identical ephemeral BLE frame keys", bleFrameKeyA, bleFrameKeyB)
        assertFalse("BLE frame key must be domain-separated from W2P2 session key", bleFrameKeyA.contentEquals(sessionKeyA))
        assertArrayEquals(sessionKeyA, comboKey)

        assertEquals(64, tokenA.length)
        assertTrue("Session token must be lowercase hex", tokenA.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals("Both peers must derive identical session bearer tokens", tokenA, tokenB)
        assertEquals(tokenA, comboToken)

        // Ensure BLE frame payload encrypted under pairA/pairB ephemeral key cannot be decrypted under another pair or static string
        val payload = "ephemeral-ble-metadata-and-archive".toByteArray(StandardCharsets.UTF_8)
        val encrypted = GlideDropNode.encryptAesGcm(payload, bleFrameKeyA)
        assertArrayEquals(payload, testDecryptAesGcm(encrypted, bleFrameKeyB))

        val pairC = GlideDropNode.generateEphemeralEcdhKeyPair()
        val wrongKey = GlideDropNode.deriveBleFrameKey(pairC.privateKey, pairB.publicKey.encoded)
        try {
            testDecryptAesGcm(encrypted, wrongKey)
            fail("Decrypting ADRE payload with wrong ephemeral ECDH key must fail")
        } catch (_: java.security.GeneralSecurityException) {
            // Expected
        }
    }

    @Test
    fun crossLanguageBleFrameKeyAndSessionTokenVectorMatchesSwift() {
        val p2Data = ByteArray(32) { (it + 33).toByte() }
        val s = BigInteger(1, p2Data)

        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val ecSpec = params.getParameterSpec(ECParameterSpec::class.java)
        val priv2 = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(s, ecSpec))

        val pub1Der = Base64.getDecoder().decode(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUVw9brnjlrkE0/7Kf1T9zQzB6Ze/N13KUVrQpsO0A19FNr46UPMY+/mlR1kCoiFQK+8NV+CMU7LMClbxfZ+TVA=="
        )

        val bleFrameKey = GlideDropNode.deriveBleFrameKey(priv2, pub1Der)
        val sessionToken = GlideDropNode.deriveSessionToken(priv2, pub1Der)
        val (comboKey, comboToken) = GlideDropNode.deriveSessionKeyAndToken(priv2, pub1Der)

        assertEquals("yC4CQspFyUEHQ8fiY9BhEhGOrB0F1UGUUtwaSF3WA/4=", Base64.getEncoder().encodeToString(comboKey))
        assertEquals(sessionToken, comboToken)

        val rawSecret = GlideDropNode.deriveEcdhRawSecret(priv2, pub1Der)
        val expectedBle = MessageDigest.getInstance("SHA-256").run {
            update(rawSecret)
            update("GlideDrop-v2-BleFrameKey".toByteArray(StandardCharsets.UTF_8))
            digest()
        }
        val expectedToken = MessageDigest.getInstance("SHA-256").run {
            update(rawSecret)
            update("GlideDrop-v2-BearerToken".toByteArray(StandardCharsets.UTF_8))
            digest().joinToString("") { "%02x".format(java.util.Locale.US, it) }
        }
        assertArrayEquals(expectedBle, bleFrameKey)
        assertEquals(expectedToken, sessionToken)
        // Hardcoded literal check matching Swift CryptoKit vector:
        assertEquals("YrIYKl4YCHCjpy5kHceecyO0ix53rFC6MNbj+dzP6Rg=", Base64.getEncoder().encodeToString(bleFrameKey))
        assertEquals("e17df0a3f490020f6fa1834856fca83007dbf426c3a07f58207eb1adb31b415e", sessionToken)
    }

    @Test
    fun sha256FingerprintValidationRejectsEmptyAndMalformedPins() {
        val valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        assertTrue(GlideDropNode.isValidSha256Fingerprint(valid))
        assertTrue(GlideDropNode.isValidSha256Fingerprint(valid.uppercase().chunked(2).joinToString(":")))
        assertFalse(GlideDropNode.isValidSha256Fingerprint(null))
        assertFalse(GlideDropNode.isValidSha256Fingerprint(""))
        assertFalse(GlideDropNode.isValidSha256Fingerprint("   "))
        assertFalse(GlideDropNode.isValidSha256Fingerprint("012345"))
        assertFalse(GlideDropNode.isValidSha256Fingerprint("z".repeat(64)))
    }

    @Test
    fun w2p2JoinReplyTimeoutAccommodatesMacDhcpAndInteractivePrompt() {
        assertTrue(
            "Android W2P2 joinReply timeout must exceed Mac 60s prompt + 25s DHCP + overhead",
            GlideDropNode.W2P2_JOIN_REPLY_TIMEOUT_MS >= 95_000L
        )
        assertTrue(
            "Android ADRE ACK timeout must accommodate Mac 60s interactive prompt",
            GlideDropNode.ADRE_ACK_TIMEOUT_MS >= 60_000L
        )
    }

    @Test
    fun validPeerTransferIpAndCidrValidationHandlesRfc1918AndDynamicSubnets() {
        // Exact RFC 1918 172.16.0.0/12 boundaries
        assertFalse(GlideDropNode.isValidPeerTransferIp("172.15.255.255"))
        assertTrue(GlideDropNode.isValidPeerTransferIp("172.16.0.1"))
        assertTrue(GlideDropNode.isValidPeerTransferIp("172.31.255.254"))
        assertFalse(GlideDropNode.isValidPeerTransferIp("172.32.0.1"))

        // Reject loopback, unspecified, multicast, public IPv4/IPv6
        assertFalse(GlideDropNode.isValidPeerTransferIp("127.0.0.1"))
        assertFalse(GlideDropNode.isValidPeerTransferIp("::1"))
        assertFalse(GlideDropNode.isValidPeerTransferIp("8.8.8.8"))
        assertFalse(GlideDropNode.isValidPeerTransferIp("2606:4700:4700::1111"))

        // Accept IPv6 link-local & ULA
        assertTrue(GlideDropNode.isValidPeerTransferIp("fe80::1%awdl0"))
        assertTrue(GlideDropNode.isValidPeerTransferIp("fd12:3456::1"))

        // Dynamic P2P subnet CIDR check & fail-closed invalid/zero prefix handling
        val cidr = GlideDropNode.computeNetworkCidr("192.168.73.129", 25)
        assertEquals("192.168.73.128/25", cidr)
        assertNull(GlideDropNode.computeNetworkCidr("192.168.73.129", 0))
        assertNull(GlideDropNode.computeNetworkCidr("192.168.73.129", -1))
        assertNull(GlideDropNode.computeNetworkCidr("192.168.73.129", 33))
        assertNull(GlideDropNode.computeNetworkCidr("", 24))
        assertNull(GlideDropNode.computeNetworkCidr("not-an-ip", 24))
        assertNull(GlideDropNode.parseCidr("0.0.0.0/0"))
        assertNull(GlideDropNode.parseCidr("::/0"))
        val parsed = listOf(GlideDropNode.parseCidr(cidr!!)!!)
        assertTrue(GlideDropNode.isIpInCidrList("192.168.73.200", parsed))
        assertFalse(GlideDropNode.isIpInCidrList("192.168.73.10", parsed))
    }

    @Test
    fun receiverClientAllowedEnforcesActiveP2pCidrAndDeniesLoopbackByDefault() {
        // With no active P2P subnet (emptyList), no P2P IP is allowed by default
        assertFalse(GlideDropNode.isReceiverClientAllowed("192.168.49.1"))
        assertFalse(GlideDropNode.isReceiverClientAllowed("192.168.73.42"))
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("192.168.49.1", hasActiveSessionToken = false))

        val dynamicSubnets = listOf(GlideDropNode.parseCidr("192.168.73.0/24")!!)
        assertTrue(GlideDropNode.isReceiverClientAllowed("192.168.73.42", dynamicSubnets))
        assertFalse(GlideDropNode.isReceiverClientAllowed("192.168.49.42", dynamicSubnets))
        assertFalse(GlideDropNode.isReceiverClientAllowed("127.0.0.1", dynamicSubnets))
        assertFalse(GlideDropNode.isReceiverClientAllowed("::1", dynamicSubnets))
        assertTrue(GlideDropNode.isReceiverClientAllowed("127.0.0.1", dynamicSubnets, allowLoopback = true))

        // A session token must not bypass strict active-P2P-subnet admission.
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("192.168.1.42", dynamicSubnets, hasActiveSessionToken = false))
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("192.168.1.42", dynamicSubnets, hasActiveSessionToken = true))
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("8.8.8.8", dynamicSubnets, hasActiveSessionToken = true))
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("127.0.0.1", dynamicSubnets, hasActiveSessionToken = true))
    }

    @Test
    fun productionAndroidSourcesContainNoHardcodedP2pIpDefaults() {
        val cwd = File(System.getProperty("user.dir") ?: ".")
        val androidMainDir = listOf(
            File(cwd, "src/main/java/io/github/jakharamit44/glidedrop"),
            File(cwd, "app/src/main/java/io/github/jakharamit44/glidedrop"),
            File(cwd, "android/app/src/main/java/io/github/jakharamit44/glidedrop")
        ).firstOrNull { it.isDirectory }
        assertTrue("Expected Android main source directory under ${cwd.absolutePath}", androidMainDir != null)
        val prodFiles = listOf(
            File(androidMainDir!!, "GlideDropNode.kt"),
            File(androidMainDir, "EmbeddedProxyServer.kt")
        )
        val forbidden = Regex("DEFAULT_P2P_|192\\.168\\.49|defaultP2pSubnets")
        for (f in prodFiles) {
            assertTrue("Expected production file to exist: ${f.absolutePath}", f.isFile)
            val content = f.readText(StandardCharsets.UTF_8)
            assertFalse(
                "Forbidden hardcoded P2P default found in ${f.name}",
                forbidden.containsMatchIn(content)
            )
        }
    }

    @Test
    fun parseJoinReplyHandlesV2ThreeFieldsAndLegacyOneField() {
        val v2 = GlideDropNode.parseJoinReply("OK 192.168.73.9\t9772\t9774\n")!!
        assertEquals("192.168.73.9", v2.macIp)
        assertEquals(9772, v2.macRxPort)
        assertEquals(9774, v2.udpKeepalivePort)

        // Legacy one-field and partial replies carry no runtime ports: no compiled-in fallback is allowed.
        assertNull(GlideDropNode.parseJoinReply("OK 192.168.49.5"))
        assertNull(GlideDropNode.parseJoinReply("OK 192.168.49.5\t9772"))
        assertNull(GlideDropNode.parseJoinReply("OK 192.168.49.5\t0\t9774"))

        val tabDelim = GlideDropNode.parseJoinReply("OK\t192.168.73.11\t9775\t9776")!!
        assertEquals("192.168.73.11", tabDelim.macIp)
        assertEquals(9775, tabDelim.macRxPort)
        assertEquals(9776, tabDelim.udpKeepalivePort)
        assertNull(GlideDropNode.parseJoinReply("OKAY 192.168.49.5"))
    }

    @Test
    fun bleScanParserRejectsSpoofedStandalone0xADxxWithoutVerifiedMacService() {
        val spoofedUuid = java.util.UUID.fromString("0000ad42-0000-1000-8000-00805f9b34fb")
        val unverified = GlideDropNode.parseMacBleAdvertisement(
            serviceUuids = listOf(spoofedUuid),
            macDataBytes = null,
            deviceName = "AD-42-Attacker"
        )
        assertFalse(unverified.hasMacService)
        assertEquals(0, unverified.psm)

        // Full 16-bit PSM > 255 in MAC_BLE_DATA_UUID payload (0x0123 LE = 291) with MAC_BLE_SERVICE_UUID
        val psmBytes = byteArrayOf(0x23, 0x01) + "Studio Mac".toByteArray(StandardCharsets.UTF_8)
        val verified = GlideDropNode.parseMacBleAdvertisement(
            serviceUuids = listOf(GlideDropNode.MAC_BLE_SERVICE_UUID, spoofedUuid),
            macDataBytes = psmBytes,
            deviceName = "IgnoredName"
        )
        assertTrue(verified.hasMacService)
        assertEquals(291, verified.psm)
        assertEquals("Studio Mac", verified.displayName)

        // Non-SIG 128-bit UUID with ADxx in upper bits must NOT be parsed as a 16-bit PSM
        val nonSigUuid = java.util.UUID.fromString("1234ad42-5678-1000-8000-00805f9b34fb")
        val noPsmFromRandom128 = GlideDropNode.parseMacBleAdvertisement(
            serviceUuids = listOf(GlideDropNode.MAC_BLE_SERVICE_UUID, nonSigUuid),
            macDataBytes = null,
            deviceName = ""
        )
        assertTrue(noPsmFromRandom128.hasMacService)
        assertEquals(0, noPsmFromRandom128.psm)

        // Valid Bluetooth SIG 16-bit 0xADxx UUID alongside MAC_BLE_SERVICE_UUID extracts PSM
        val sigPsm = GlideDropNode.parseMacBleAdvertisement(
            serviceUuids = listOf(GlideDropNode.MAC_BLE_SERVICE_UUID, spoofedUuid),
            macDataBytes = null,
            deviceName = ""
        )
        assertTrue(sigPsm.hasMacService)
        assertEquals(0x42, sigPsm.psm)
    }

    @Test
    fun sessionBearerTokenValidationEnforcesMatchAndExpiry() {
        val tok = "a1b2c3d4".repeat(8)
        val now = 1_700_000_000_000L
        val active = mapOf(tok to (now + 60_000L))
        assertTrue(GlideDropNode.isValidSessionBearerToken(tok, active, now))
        assertTrue(GlideDropNode.isValidSessionBearerToken("  ${tok.uppercase()}  ", active, now))
        assertFalse(GlideDropNode.isValidSessionBearerToken("f".repeat(64), active, now))
        assertFalse(GlideDropNode.isValidSessionBearerToken(tok, active, now + 60_001L))
        assertFalse(GlideDropNode.isValidSessionBearerToken("short", active, now))
    }

    @Test
    fun httpChunkedReaderRejectsNegativeAndMalformedChunkSizes() {
        val valid = "5\r\nhello\r\n0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        val validBody = GlideDropNode.readHttpBodyBytesBounded(
            ByteArrayInputStream(valid),
            mapOf("transfer-encoding" to "chunked")
        )
        assertEquals("hello", String(validBody, StandardCharsets.US_ASCII))

        // Negative hex chunk size "-1" must throw HttpFramingException(400) (subclass of IOException, never IndexOutOfBoundsException)
        val negChunk = "-1\r\nhello\r\n0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.openHttpBodyStream(
                ByteArrayInputStream(negChunk),
                mapOf("transfer-encoding" to "chunked")
            ).readBytes()
            fail("Negative chunk size '-1' must be rejected")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(400, e.statusCode)
        }

        // Non-hex chunk size must throw HttpFramingException(400)
        val badHex = "xyz\r\n0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.openHttpBodyStream(
                ByteArrayInputStream(badHex),
                mapOf("transfer-encoding" to "chunked")
            ).readBytes()
            fail("Malformed chunk size 'xyz' must be rejected")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(400, e.statusCode)
        }

        // Missing CRLF after chunk payload must throw HttpFramingException(400)
        val badTerminator = "5\r\nhelloXX0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.openHttpBodyStream(
                ByteArrayInputStream(badTerminator),
                mapOf("transfer-encoding" to "chunked")
            ).readBytes()
            fail("Missing CRLF after chunk must be rejected")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(400, e.statusCode)
        }
    }

    @Test
    fun httpRequestHeadEnforcesHeaderLimitsAndNumericValidation() {
        // 1. > 64 header lines -> 431
        val tooManyHeaders = buildString {
            append("POST /Discover HTTP/1.1\r\n")
            for (i in 1..65) append("X-H$i: val\r\n")
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.readHttpRequestHead(ByteArrayInputStream(tooManyHeaders))
            fail("Expected 431 for >64 headers")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(431, e.statusCode)
        }

        // 2. > 16,384 cumulative header bytes -> 431
        val oversizedHeaders = buildString {
            append("POST /Discover HTTP/1.1\r\n")
            for (i in 1..4) append("X-Big-$i: ${"A".repeat(4500)}\r\n")
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.readHttpRequestHead(ByteArrayInputStream(oversizedHeaders))
            fail("Expected 431 for >16KB headers")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(431, e.statusCode)
        }

        // 3. > 8,192 single line -> 431
        val longLine = "POST /Discover HTTP/1.1\r\nX-Long: ${"B".repeat(8200)}\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.readHttpRequestHead(ByteArrayInputStream(longLine))
            fail("Expected 431 for >8KB line")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(431, e.statusCode)
        }

        // 4. Invalid Content-Length, TotalBytes, duplicate Content-Length, CL+TE -> 400
        val badRequests = listOf(
            "POST /Discover HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            "POST /Upload HTTP/1.1\r\nTotalBytes: -5\r\n\r\n",
            "POST /Ask HTTP/1.1\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /Ask HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n",
            "POST /Ask HTTP/1.1\r\nBad Header: 1\r\n\r\n"
        )
        for (req in badRequests) {
            try {
                GlideDropNode.readHttpRequestHead(ByteArrayInputStream(req.toByteArray(StandardCharsets.US_ASCII)))
                fail("Expected 400 Bad Request for: $req")
            } catch (e: GlideDropNode.HttpFramingException) {
                assertEquals(400, e.statusCode)
            }
        }
    }

    @Test
    fun httpMetaBodyReadCapsNonUploadPayloadsAtOneMebibyte() {
        val exactMax = ByteArray(GlideDropNode.MAX_HTTP_META_BODY_BYTES) { 0x41 }
        val ok = GlideDropNode.readHttpBodyBytesBounded(
            ByteArrayInputStream(exactMax),
            mapOf("content-length" to exactMax.size.toString())
        )
        assertEquals(GlideDropNode.MAX_HTTP_META_BODY_BYTES, ok.size)

        try {
            GlideDropNode.readHttpBodyBytesBounded(
                ByteArrayInputStream(ByteArray(0)),
                mapOf("content-length" to (GlideDropNode.MAX_HTTP_META_BODY_BYTES + 1).toString())
            )
            fail("Declared Content-Length > 1 MiB must fail with 413")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(413, e.statusCode)
        }

        val chunkPayload = "A".repeat(GlideDropNode.MAX_HTTP_META_BODY_BYTES + 1)
        val chunkedWire = (Integer.toHexString(chunkPayload.length) + "\r\n" + chunkPayload + "\r\n0\r\n\r\n")
            .toByteArray(StandardCharsets.US_ASCII)
        try {
            GlideDropNode.readHttpBodyBytesBounded(
                ByteArrayInputStream(chunkedWire),
                mapOf("transfer-encoding" to "chunked")
            )
            fail("Chunked body > 1 MiB must fail with 413")
        } catch (e: GlideDropNode.HttpFramingException) {
            assertEquals(413, e.statusCode)
        }
    }

    @Test
    fun pendingMacTxAtomicClaimAllowsOnlySingleWinnerUnderConcurrency() {
        val tx = GlideDropNode.PendingMacTx(
            metaBytes = ByteArray(4),
            archiveBytes = ByteArray(0),
            entries = emptyList(),
            url = "https://example.com",
            label = "test",
            fileCount = 1,
            totalRawBytes = 0L,
            result = kotlinx.coroutines.CompletableDeferred()
        )
        val threads = 8
        val startGate = java.util.concurrent.CountDownLatch(1)
        val doneGate = java.util.concurrent.CountDownLatch(threads)
        val wins = java.util.concurrent.atomic.AtomicInteger(0)
        val pool = Executors.newFixedThreadPool(threads)
        try {
            repeat(threads) {
                pool.submit {
                    startGate.await()
                    if (tx.tryClaim()) wins.incrementAndGet()
                    doneGate.countDown()
                }
            }
            startGate.countDown()
            assertTrue(doneGate.await(5, TimeUnit.SECONDS))
            assertEquals(1, wins.get())
            assertTrue(tx.isClaimed)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun wifiDirectPostTransferActionPreservesReuseOnSuccessAndCleansOrphanedLanGroup() {
        assertEquals(
            GlideDropNode.WifiDirectPostTransferAction.PRESERVE_FOR_REUSE_AND_SCHEDULE_TEARDOWN,
            GlideDropNode.resolveWifiDirectPostTransferAction(
                txSuccess = true,
                transferCancelled = false,
                isP2pHost = true,
                hasWifiDirectCreds = true
            )
        )
        assertEquals(
            GlideDropNode.WifiDirectPostTransferAction.CLEAR_AND_STOP_GROUP_NOW,
            GlideDropNode.resolveWifiDirectPostTransferAction(
                txSuccess = false,
                transferCancelled = false,
                isP2pHost = true,
                hasWifiDirectCreds = true
            )
        )
        assertEquals(
            GlideDropNode.WifiDirectPostTransferAction.CLEAR_AND_STOP_GROUP_NOW,
            GlideDropNode.resolveWifiDirectPostTransferAction(
                txSuccess = true,
                transferCancelled = true,
                isP2pHost = true,
                hasWifiDirectCreds = true
            )
        )
        assertEquals(
            GlideDropNode.WifiDirectPostTransferAction.CLEAR_AND_STOP_GROUP_NOW,
            GlideDropNode.resolveWifiDirectPostTransferAction(
                txSuccess = true,
                transferCancelled = false,
                isP2pHost = false,
                hasWifiDirectCreds = true
            )
        )
        assertEquals(
            GlideDropNode.WifiDirectPostTransferAction.CLEAR_ONLY,
            GlideDropNode.resolveWifiDirectPostTransferAction(
                txSuccess = true,
                transferCancelled = false,
                isP2pHost = false,
                hasWifiDirectCreds = false
            )
        )
    }

    @Test
    fun receiverClientAllowedRejectsMappedLoopbackAndRestrictedIpsEvenWithSessionToken() {
        val dynamicSubnets = listOf(GlideDropNode.parseCidr("192.168.73.0/24")!!)
        for (blocked in listOf("::ffff:127.0.0.1", "::", "0.0.0.0", "100.64.0.1", "169.254.169.254")) {
            assertFalse(
                "Expected $blocked to be rejected even with active session token",
                GlideDropNode.isReceiverRequestClientAllowed(blocked, dynamicSubnets, hasActiveSessionToken = true)
            )
        }
    }

    @Test
    fun largeFilesRefuseAutomaticBleFallbackAndKeepProtocolWireCap() {
        assertEquals(30_000_000L, GlideDropNode.MAX_ENCRYPTED_BLE_ARCHIVE_BYTES)
        assertEquals(5_000_000L, GlideDropNode.MAX_BLE_AUTO_FALLBACK_BYTES)
        assertTrue(GlideDropNode.shouldAllowBleAutoFallback(0L, hasEntries = false))
        assertTrue(GlideDropNode.shouldAllowBleAutoFallback(5_000_000L, hasEntries = true))
        assertFalse(GlideDropNode.shouldAllowBleAutoFallback(5_000_001L, hasEntries = true))
        assertFalse(GlideDropNode.shouldAllowBleAutoFallback(25_000_000L, hasEntries = true))
    }
}
