package com.mo1ty.mqtt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

public class EncryptedPayload {

    public String encryptedMessage;
    public String algorithmIdentifier;

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
