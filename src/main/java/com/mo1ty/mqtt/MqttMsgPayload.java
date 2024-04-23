package com.mo1ty.mqtt;

import java.security.cert.X509Certificate;

public class MqttMsgPayload {

    public MessageStruct messageStruct;
    public byte[] signature;
    public X509Certificate x509Certificate;

}
