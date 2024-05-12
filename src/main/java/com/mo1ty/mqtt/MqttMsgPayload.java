package com.mo1ty.mqtt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

public class MqttMsgPayload implements Serializable {

    public MessageStruct messageStruct;
    public byte[] signature;
    public byte[] x509Certificate;



    public String toJsonString() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writer().writeValueAsString(this);
    }

    public static MqttMsgPayload getFromJsonString(byte[] jsonString) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonStr = new String(jsonString, StandardCharsets.UTF_8);
        return objectMapper.reader().readValue(jsonStr, MqttMsgPayload.class);
    }
}
