package com.mo1ty.security.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.Security;

public class KyberClientUtil {

    public BCKyberPublicKey publicKey;

    public KyberClientUtil(){
        if(Security.getProvider("BCPQC") == null){
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
        publicKey = null;
    }

    public PublicKey pubKeyFromBytes(byte[] pubKeyBytes) throws Exception {
        SubjectPublicKeyInfo kyberKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(pubKeyBytes));
        return new BCKyberPublicKey(kyberKeyInfo);
    }

    public byte[] wrap(PublicKey publicKey, SecretKey secret) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("kyber1024", "BCPQC");
        encryptionCipher.init(Cipher.WRAP_MODE, publicKey);
        return encryptionCipher.wrap(secret);
    }


}
