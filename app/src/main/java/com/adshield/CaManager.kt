package com.adshield

import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.StringReader
import java.io.StringWriter

/**
 * Local Certificate Authority for the HTTPS path filter (v0.8.0).
 *
 * To see URL paths inside HTTPS (e.g. pornhub.com/_xa/ads), the VPN must
 * terminate the client's TLS with a forged per-domain certificate. Clients
 * only trust it if the user installs this CA (one-time, via the system
 * install UI the app launches).
 *
 *  - CA: RSA-2048, self-signed, CA:true, 10-year validity, stored as PEM
 *    in the app's private files (never leaves the device).
 *  - Server certs: RSA-2048, CN+SAN=host, signed by the CA, 825-day
 *    validity (browser limit), cached in memory.
 *
 * Pure JVM + BouncyCastle (no Android APIs except the files dir passed in),
 * so generation and verification are unit-testable on the JVM.
 */
class CaManager(private val filesDir: File) {

    data class Ca(val key: PrivateKey, val cert: X509Certificate)

    private val serverCertCache = ConcurrentHashMap<String, KeyStore>()

    init {
        // Android ships an old, stripped-down BouncyCastle as "BC" which
        // lacks SHA256withRSA signer support. Replace it with our bundled
        // (complete) BouncyCastle so cert generation works.
        try {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        } catch (_: Exception) {}
        try {
            Security.addProvider(BouncyCastleProvider())
        } catch (_: Exception) {}
    }

    private fun caKeyFile() = File(filesDir, "mitm_ca.key.pem")
    private fun caCertFile() = File(filesDir, "mitm_ca.cert.pem")

    /** Loads the CA, generating and persisting it on first run. */
    @Synchronized
    fun getOrCreateCa(): Ca {
        if (caKeyFile().exists() && caCertFile().exists()) {
            try {
                return Ca(loadPrivateKey(caKeyFile()), loadCert(caCertFile()))
            } catch (_: Exception) {
                // Corrupt files: regenerate below.
            }
        }
        val kp = generateRsaKeyPair()
        val now = Date()
        val notAfter = Date(now.time + 10L * 365 * 24 * 3600 * 1000)
        val name = X500Name("CN=AdShield Local CA,O=AdShield,C=IN")
        val builder = X509v3CertificateBuilder(
            name,
            BigInteger(64, SecureRandom()).abs(),
            Date(now.time - 24 * 3600 * 1000),
            notAfter,
            name,
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.public.encoded)
        )
        val extUtils = JcaX509ExtensionUtils()
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(
            Extension.keyUsage, true,
            KeyUsage(KeyUsage.keyCertSign or KeyUsage.digitalSignature or KeyUsage.cRLSign)
        )
        builder.addExtension(
            Extension.subjectKeyIdentifier, false,
            extUtils.createSubjectKeyIdentifier(kp.public)
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(kp.private)
        val cert = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))
        cert.verify(kp.public)
        writePem(caKeyFile(), "PRIVATE KEY", kp.private.encoded)
        writePem(caCertFile(), "CERTIFICATE", cert.encoded)
        return Ca(kp.private, cert)
    }

    /** PEM bytes of the CA certificate, for the system install intent. */
    fun caCertPem(): ByteArray = caCertFile().readBytes()

    /**
     * KeyStore holding a freshly minted server key+cert for [host],
     * signed by the CA. Cached per host; the KeyStore password is fixed
     * and internal (never user-visible).
     */
    fun serverKeyStore(host: String): KeyStore {
        val clean = host.trim().lowercase().trim('.')
        return serverCertCache.getOrPut(clean) {
            val ca = getOrCreateCa()
            val kp = generateRsaKeyPair()
            val now = Date()
            // 825 days: the browser-trusted leaf validity cap.
            val notAfter = Date(now.time + 825L * 24 * 3600 * 1000)
            // Use the CA subject's exact DER: name-chaining compares
            // encodings, and a string roundtrip can alter them.
            val issuer = X500Name.getInstance(ca.cert.subjectX500Principal.encoded)
            val subject = X500Name("CN=$clean")
            val builder = X509v3CertificateBuilder(
                issuer,
                BigInteger(64, SecureRandom()).abs(),
                Date(now.time - 24 * 3600 * 1000),
                notAfter,
                subject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.public.encoded)
            )
            val extUtils = JcaX509ExtensionUtils()
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            builder.addExtension(
                Extension.keyUsage, true,
                KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
            )
            builder.addExtension(
                Extension.extendedKeyUsage, false,
                org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                    org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth
                )
            )
            builder.addExtension(
                Extension.subjectAlternativeName, false,
                GeneralNames(arrayOf(
                    GeneralName(GeneralName.dNSName, clean),
                    GeneralName(GeneralName.dNSName, "*.$clean")
                ))
            )
            builder.addExtension(
                Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(ca.cert)
            )
            val signer = JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(ca.key)
            val cert = JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer))
            cert.verify(ca.cert.publicKey)
            val ks = KeyStore.getInstance(KeyStore.getDefaultType())
            ks.load(null, null)
            ks.setKeyEntry(
                "server", kp.private, KEYSTORE_PASSWORD,
                arrayOf(cert, ca.cert)
            )
            ks
        }
    }

    private fun generateRsaKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        return kpg.generateKeyPair()
    }

    private fun writePem(file: File, type: String, der: ByteArray) {
        StringWriter().use { sw ->
            PemWriter(sw).use { pw -> pw.writeObject(PemObject(type, der)) }
            file.writeText(sw.toString())
        }
    }

    private fun loadPrivateKey(file: File): PrivateKey {
        PemReader(StringReader(file.readText())).use { reader ->
            val obj = reader.readPemObject()
                ?: throw IllegalStateException("empty PEM")
            val spec = java.security.spec.PKCS8EncodedKeySpec(obj.content)
            return java.security.KeyFactory.getInstance("RSA").generatePrivate(spec)
        }
    }

    private fun loadCert(file: File): X509Certificate {
        file.inputStream().use { ins ->
            return CertificateFactory.getInstance("X.509")
                .generateCertificate(ins) as X509Certificate
        }
    }

    companion object {
        private val KEYSTORE_PASSWORD = "adshield-mitm".toCharArray()

        internal fun keyStorePassword(): CharArray = KEYSTORE_PASSWORD
    }
}
