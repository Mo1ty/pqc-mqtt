package com.mo1ty.security.cert;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

public interface CertificateGenerator {

    KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;

    X509Certificate genSelfSignedCert() throws Exception;

    X509Certificate genSelfSignedCert(KeyPair keyPair, Long certValidityMillis) throws Exception;
}
