package com.mo1ty.security.fulltrust;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertGen {

    public CertGen(){
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        bcp.addAlgorithm("Signature.SHA512withFALCON-1024", "Falcon-1024");
        //var1.addAlgorithm("Signature.SHA3-512WITHDDSA", "org.bouncycastle.jcajce.provider.asymmetric.dsa.DSASigner$detDSASha3_512");

        Security.addProvider(bcp);
        //Security.addProvider(new BouncyCastlePQCProvider());
    }

    // preferred to use with "Falcon"
    public KeyPair generateKeyPair(String algorithmInstance, Integer keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmInstance, "BC");
        keyPairGenerator.initialize(FalconParameterSpec.falcon_1024, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    // Automatic falcon certificate generation - 1 day length.
    public X509Certificate genSelfSignedCert() throws Exception {
        return genSelfSignedCert(generateKeyPair("Falcon", 1024), 0L);
    }


    public X509Certificate genSelfSignedCert(Long certValidityMillis) throws Exception {
        return genSelfSignedCert(generateKeyPair("Falcon", 1024), certValidityMillis);
    }


    public X509Certificate genSelfSignedCert(KeyPair keyPair, Long certValidityMillis) throws Exception {

        //if (Security.getProvider("BCPQC") == null)
        //{
        //    Security.addProvider(new BouncyCastlePQCProvider());
        //}

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        X500NameBuilder builder = standardInfoBuilder();

        // Begin date is yesterday to prevent bugs. End date is now plus how long we want it to be valid plus 1 day.
        Time validityBeginTime = new Time(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
        Time validityEndTime = new Time(new Date(System.currentTimeMillis() + certValidityMillis));

        ContentSigner sigGen = new JcaContentSignerBuilder("Falcon-1024").setProvider("BC").build(privKey);

        // Create the certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                builder.build(),
                BigInteger.valueOf(System.currentTimeMillis()),
                validityBeginTime,
                validityEndTime,
                builder.build(),
                pubKey);

        X509Certificate baseCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(sigGen));

        return baseCert;
    }

    public byte[] signMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature falconSign = Signature.getInstance("Falcon-1024", "BC");
        falconSign.initSign(keyPair.getPrivate());
        falconSign.update(message);
        byte[] signature = falconSign.sign();
        return signature;
    }

    public byte[] hashAndSignMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature falconSign = Signature.getInstance("Falcon-1024", "BC");
        falconSign.initSign(keyPair.getPrivate());
        byte[] digestedMessage = messageDigest.digest(message);
        falconSign.update(digestedMessage);
        return falconSign.sign();
    }

    public boolean verifyMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature falconVerify = Signature.getInstance("Falcon-1024", "BC");
        falconVerify.initVerify(publicKey);
        falconVerify.update(message);
        return falconVerify.verify(signature);
    }

    public boolean verifyHashedMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature falconVerify = Signature.getInstance("Falcon-1024", "BC");
        falconVerify.initVerify(publicKey);
        byte[] digestedMessage = messageDigest.digest(message);
        falconVerify.update(digestedMessage);
        return falconVerify.verify(signature);
    }

    private static X500NameBuilder standardInfoBuilder()
    {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        builder.addRDN(BCStyle.C, "AU");
        builder.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        builder.addRDN(BCStyle.L, "Melbourne");
        builder.addRDN(BCStyle.ST, "Victoria");
        builder.addRDN(BCStyle.E, "feedback-crypto@bouncycastle.org");

        return builder;
    }


}
