package com.mo1ty.mqtt;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;

public class MessageStruct implements Serializable {

    public String plainMessage;
    public Timestamp timestamp;
    public String mqttTopic;

    public MessageStruct(String plainTextMsg, String topic){
        plainMessage = plainTextMsg;
        mqttTopic = topic;

        timestamp = new Timestamp(System.currentTimeMillis());
    }

    public MessageStruct(){}

    public MessageStruct(String plainTextMsg, String topic, Timestamp timestamp){
        plainMessage = plainTextMsg;
        mqttTopic = topic;

        this.timestamp = timestamp;
    }

    @Override
    public String toString() {
        return "MessageStruct{" +
                "plainMessage='" + plainMessage +
                ", timestamp=" + timestamp +
                ", mqttTopic='" + mqttTopic + "'" +
                "}";
    }

    public byte[] getBytes(){
        return this.toString().getBytes(StandardCharsets.UTF_8);
    }

}
