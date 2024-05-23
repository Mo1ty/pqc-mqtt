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

public class FalconGen implements CertGen {

    public FalconGen(){
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    // preferred to use with "Falcon"
    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("falcon", "BC");
        keyPairGenerator.initialize(FalconParameterSpec.falcon_1024, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public X509Certificate genSelfSignedCert(KeyPair keyPair, Long certValidityMillis) throws Exception {

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

    @Override
    public byte[] signMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature falconSign = Signature.getInstance("Falcon-1024", "BC");
        falconSign.initSign(keyPair.getPrivate());
        falconSign.update(message);
        return falconSign.sign();
    }

    @Override
    public byte[] hashAndSignMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature falconSign = Signature.getInstance("Falcon-1024", "BC");
        falconSign.initSign(keyPair.getPrivate());
        byte[] digestedMessage = messageDigest.digest(message);
        falconSign.update(digestedMessage);
        return falconSign.sign();
    }

    @Override
    public boolean verifyMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature falconVerify = Signature.getInstance("Falcon-1024", "BC");
        falconVerify.initVerify(publicKey);
        falconVerify.update(message);
        return falconVerify.verify(signature);
    }

    @Override
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
