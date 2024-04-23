package com.mo1ty.mqtt;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;

public class MessageStruct {

    public String plainMessage;
    public Timestamp timestamp;
    public String mqttTopic;

    public MessageStruct(String plainTextMsg, String topic){
        plainMessage = plainTextMsg;
        mqttTopic = topic;

        timestamp = new Timestamp(System.currentTimeMillis());
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
