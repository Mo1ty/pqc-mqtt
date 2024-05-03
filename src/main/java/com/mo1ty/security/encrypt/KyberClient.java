package com.mo1ty.security.encrypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.*;

public class KyberClient {

    public KyberClient(){
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public byte[] encrypt(PublicKey publicKey, byte[] payload) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("Kyber-1024", "BC");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptionCipher.doFinal(payload);
    }
}
