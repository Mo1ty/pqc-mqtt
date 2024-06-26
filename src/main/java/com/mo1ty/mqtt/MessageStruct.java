package com.mo1ty.mqtt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;

public class MessageStruct implements Serializable {

    public String plainMessage;
    public Long timestamp;
    public String mqttTopic;

    public MessageStruct(String plainTextMsg, String topic){
        plainMessage = plainTextMsg;
        mqttTopic = topic;

        timestamp = new Timestamp(System.currentTimeMillis()).getTime();
    }

    public MessageStruct(){}

    public MessageStruct(String plainTextMsg, String topic, Timestamp timestamp){
        plainMessage = plainTextMsg;
        mqttTopic = topic;
        this.timestamp = timestamp.getTime();
    }

    @Override
    public String toString() {
        return "MessageStruct{" +
                    "plainMessage='" + plainMessage +
                    ", timestamp=" + timestamp +
                    ", mqttTopic='" + mqttTopic + "'" +
                    "}";
    }

    public byte[] toJsonStringAsBytes() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writer().writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static MessageStruct getFromBytes(byte[] message) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(new String(message, StandardCharsets.UTF_8), MessageStruct.class);
    }

}
