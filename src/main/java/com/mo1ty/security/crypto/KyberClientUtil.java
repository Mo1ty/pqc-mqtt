package com.mo1ty.security.crypto;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.kyber.BCKyberPublicKey;

import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.Security;

public class KyberClientUtil {

    public BCKyberPublicKey publicKey;

    public KyberClientUtil(){
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void pubKeyFromBytes(byte[] pubKeyBytes) throws Exception {
        SubjectPublicKeyInfo kyberKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(pubKeyBytes));
        publicKey = new BCKyberPublicKey(kyberKeyInfo);
    }

    public byte[] encrypt(PublicKey publicKey, byte[] payload) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("Kyber-1024", "BC");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptionCipher.doFinal(payload);
    }

}
