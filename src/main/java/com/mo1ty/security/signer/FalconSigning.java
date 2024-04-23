package com.mo1ty.security.signer;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.jcajce.provider.falcon.SignatureSpi;
import java.security.*;

public class FalconSigning extends SignatureSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {

    private Digest digest;
    private FalconSigner signer;
    private SecureRandom random;

    protected FalconSigning(FalconSigner falconSigner) {
        super(falconSigner);
    }

    protected FalconSigning(FalconSigner falconSigner, FalconParameters falconParameters) {
        super(falconSigner, falconParameters);
    }

    /*
    public static class detFalconSha3_512 extends FalconSigning {
        public detFalconSha3_512() {
            super(DigestFactory.createSHA3_512(), new org.bouncycastle.pqc.crypto.falcon.FalconSigner());
        }
    }
    */
}
