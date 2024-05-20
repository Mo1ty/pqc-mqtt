package com.mo1ty.security.fulltrust;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class DilithiumGen implements CertGen {

    public DilithiumGen(){
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    // preferred to use with "Dilithium"
    public KeyPair generateKeyPair(String algorithmInstance) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithmInstance, "BC");
        keyPairGenerator.initialize(DilithiumParameterSpec.dilithium5, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }


    public X509Certificate genSelfSignedCert(KeyPair keyPair, Long certValidityMillis) throws Exception {

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        X500NameBuilder builder = standardInfoBuilder();

        // Begin date is yesterday to prevent bugs. End date is now plus how long we want it to be valid plus 1 day.
        Time validityBeginTime = new Time(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
        Time validityEndTime = new Time(new Date(System.currentTimeMillis() + certValidityMillis));

        ContentSigner sigGen = new JcaContentSignerBuilder("dilithium5").setProvider("BC").build(privKey);

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
        Signature dilithiumSign = Signature.getInstance("dilithium5", "BC");
        dilithiumSign.initSign(keyPair.getPrivate());
        dilithiumSign.update(message);
        return dilithiumSign.sign();
    }

    public byte[] hashAndSignMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature dilithiumSign = Signature.getInstance("dilithium5", "BC");
        dilithiumSign.initSign(keyPair.getPrivate());
        byte[] digestedMessage = messageDigest.digest(message);
        dilithiumSign.update(digestedMessage);
        return dilithiumSign.sign();
    }

    public boolean verifyMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature dilithiumVerify = Signature.getInstance("dilithium5", "BC");
        dilithiumVerify.initVerify(publicKey);
        dilithiumVerify.update(message);
        return dilithiumVerify.verify(signature);
    }

    public boolean verifyHashedMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature dilithiumVerify = Signature.getInstance("dilithium5", "BC");
        dilithiumVerify.initVerify(publicKey);
        byte[] digestedMessage = messageDigest.digest(message);
        dilithiumVerify.update(digestedMessage);
        return dilithiumVerify.verify(signature);
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
