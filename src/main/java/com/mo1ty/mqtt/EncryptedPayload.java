package com.mo1ty.mqtt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

public class EncryptedPayload {

    public byte[] encryptedMessage;
    public String algorithmIdentifier;
    public byte[] signature;
    public byte[] x509Certificate;

    public EncryptedPayload(){}

    public EncryptedPayload(byte[] encryptedMessage, String algorithmIdentifier, byte[] signature, byte[] x509Certificate) {
        this.encryptedMessage = encryptedMessage;
        this.algorithmIdentifier = algorithmIdentifier;
        this.signature = signature;
        this.x509Certificate = x509Certificate;
    }

    public String toJsonString() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writer().writeValueAsString(this);
    }

    public static EncryptedPayload getFromJsonString(byte[] jsonString) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonStr = new String(jsonString, StandardCharsets.UTF_8);
        return objectMapper.reader().readValue(jsonStr, EncryptedPayload.class);
    }
}
