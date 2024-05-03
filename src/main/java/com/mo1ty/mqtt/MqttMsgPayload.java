package com.mo1ty.mqtt;

import com.mo1ty.utils.ByteUtil;
import org.bouncycastle.util.encoders.Base64;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 *
 */
public class MqttMsgPayload implements Serializable {

    public MessageStruct messageStruct;
    // This identifier sets algorithm used for payload encryption
    public String algorithmIdentifier;
    public byte[] signature;
    public byte[] x509Certificate;


    /**
     *
     * @return
     */
    public byte[] encodeInfo(){
        byte[] message = Base64.encode(messageStruct.plainMessage.getBytes());
        byte[] time = ByteUtil.longToBytes(messageStruct.timestamp.getTime());
        byte[] topic = Base64.encode(messageStruct.mqttTopic.getBytes());


        ByteBuffer buff = ByteBuffer.allocate(
                message.length + time.length + topic.length + signature.length + x509Certificate.length + 4
        );

        buff.put(message);
        buff.put(";".getBytes(StandardCharsets.UTF_8));
        buff.put(message);
        buff.put(";".getBytes(StandardCharsets.UTF_8));
        buff.put(message);
        buff.put(";".getBytes(StandardCharsets.UTF_8));
        buff.put(message);
        buff.put(";".getBytes(StandardCharsets.UTF_8));
        buff.put(message);

        return buff.array();
    }

    /*
    public String toJsonString() throws IOException {
        return JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT)
                .asString(this);
    }

    public static MqttMsgPayload getFromJsonString(byte[] jsonString) throws IOException {
        return JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT).beanFrom(MqttMsgPayload.class, jsonString);
    }


     */
}
