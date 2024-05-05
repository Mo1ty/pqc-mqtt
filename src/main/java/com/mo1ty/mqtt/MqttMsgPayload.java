package com.mo1ty.mqtt;

import com.fasterxml.jackson.jr.ob.JSON;

import java.io.Serializable;

public class MqttMsgPayload implements Serializable {

    public MessageStruct messageStruct;
    public byte[] signature;
    public byte[] x509Certificate;



    public String toJsonString() throws Exception {
        return JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT)
                .asString(this);
    }

    public static MqttMsgPayload getFromJsonString(byte[] jsonString) throws Exception {
        return JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT).beanFrom(MqttMsgPayload.class, jsonString);
    }
}
