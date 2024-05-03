package com.mo1ty.utils;

import com.mo1ty.mqtt.MessageStruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class EncryptUtil {

    public EncryptUtil(){
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public byte[] encryptMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return null;
    }

    public MessageStruct decryptMessage(byte[] encryptedMessage) {
        return null;
    }

}
