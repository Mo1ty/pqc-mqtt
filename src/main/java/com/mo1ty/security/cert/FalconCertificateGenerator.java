package com.mo1ty.security.cert;

import jdk.jshell.spi.ExecutionControl;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class FalconCertificateGenerator extends AbstractCertificateGenerator implements CertificateGenerator {

    private static final String ALG_INSTANCE = "Falcon";

    // preferred to use with "Falcon"
    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        registerProvider();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALG_INSTANCE, "BC");
        keyPairGenerator.initialize(FalconParameterSpec.falcon_1024, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public X509Certificate genSelfSignedCert() throws Exception {
        throw new ExecutionControl.NotImplementedException("IMPLEMENT WITH EXISTING CERTIFICATE!");
    }

    @Override
    public X509Certificate genSelfSignedCert(KeyPair keyPair, Long certValidityMillis) throws Exception {
        registerProvider();

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
}
