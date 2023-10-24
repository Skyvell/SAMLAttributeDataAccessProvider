import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import java.security.PrivateKey
import java.security.KeyPair

fun generateCertificate(keyPair: KeyPair): X509Certificate {
    val notBefore = Date()
    val notAfter = Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)) // Valid for 1 year

    val certBuilder = X509v3CertificateBuilder(
        X500Name("CN=Issuer"), // issuer
        BigInteger.valueOf(System.currentTimeMillis()), // serial number
        notBefore, // start of validity
        notAfter, // end of validity
        X500Name("CN=Subject"), // subject
        SubjectPublicKeyInfo.getInstance(keyPair.public.encoded) // public key info
    )
    
    val signer: ContentSigner = JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.private)

    return JcaX509CertificateConverter()
        .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        .getCertificate(certBuilder.build(signer))
}

fun generateKeys(): KeyPair {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048)
    return keyPairGenerator.generateKeyPair()
}