package com.mo1ty.mqtt;

public class EncryptedMsgPayload {

    public byte[] encryptedMessageStruct;
    public String algorithmIdentifier;
    public byte[] signature;
    public byte[] x509Certificate;

}
