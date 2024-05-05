package com.mo1ty.mqtt;

import com.fasterxml.jackson.jr.ob.JSON;

public class EncryptedPayload {

    public String encryptedMessage;
    public String algorithmIdentifier;

    public String toJsonString() throws Exception {
        return JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT)
                .asString(this);
    }

    public static MqttMsgPayload getFromJsonString(byte[] jsonString) throws Exception {
        return JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT).beanFrom(MqttMsgPayload.class, jsonString);
    }
}
