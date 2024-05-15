import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.mqtt.publisher.MqttPublisher;
import com.mo1ty.security.fulltrust.CertGen;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttAsyncClient;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Timer;
import java.util.TimerTask;

public class SecLv1PublisherApp {
    private static MqttMessage prepareQos2Message(String messageText){
        MqttMessage msg = new MqttMessage();
        msg.setQos(2);
        msg.setPayload(messageText.getBytes(StandardCharsets.UTF_8));
        return msg;
    }

    private static MqttAsyncClient createAndConnect(String connectionUrl, String connectionId) throws Exception{
        MqttAsyncClient client = new MqttAsyncClient(connectionUrl, connectionId, new MemoryPersistence());
        System.out.println("CONNECTION INITIATED!");
        IMqttToken token = client.connect();
        token.waitForCompletion();
        System.out.println("CLIENT CONNECTED!");
        return client;
    }

    private static String payloadToBytes(String message, String topic, CertGen certGen, KeyPair falconKeyPair, byte[] certificate) throws Exception{
        MessageStruct messageStruct = new MessageStruct(message, topic);
        byte[] signature = certGen.hashAndSignMessage(falconKeyPair, messageStruct.toJsonStringAsBytes());

        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = signature;
        msgPayload.x509Certificate = certificate;

        return msgPayload.toJsonString();
    }

    private static void sendMessage(String message, String topic, MqttAsyncClient client){
        try {
            client.publish(topic, prepareQos2Message(message));
            // System.out.println("Successfully published message \"" + message + "\" on topic \"" + topic + "\"!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        String connectionUrl = "tcp://192.168.0.249:1883";
        String connId = "PC_PUB_LV1";
        String topic = "test/topic";
        String testMessage = "TEST_MESSAGE";

        System.out.println(testMessage);

        MqttAsyncClient client = createAndConnect(connectionUrl, connId);

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY MESSAGES
        System.out.println("CERTIFICATE INITIATED!");
        CertGen certGen = new CertGen();
        KeyPair falconKeyPair = certGen.generateKeyPair("Falcon", 1024);
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);
        System.out.println("CERTIFICATE DONE!");

        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        MessageStruct messageStruct = new MessageStruct(testMessage, topic);
        byte[] jsStr = messageStruct.toJsonStringAsBytes();
        byte[] signature = certGen.hashAndSignMessage(falconKeyPair, jsStr);
        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = signature;
        msgPayload.x509Certificate = certificate.getEncoded();

        System.out.println("CREATING JSON STRING AS BYTES!");
        byte[] jsonData = msgPayload.toJsonString().getBytes(StandardCharsets.UTF_8);
        System.out.println("PAYLOAD SET UP!");

        System.out.println("Connected successfully!");
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    String messageBytes = payloadToBytes(testMessage, topic, certGen, falconKeyPair, certificate.getEncoded());
                    sendMessage(messageBytes, topic, client);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 1000);


        System.out.println("Message sent!");
    }

    static String encodeCert(X509Certificate certificate) throws Exception {
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";
        byte[] derCert = certificate.getEncoded();
        String pemCertPre = new String(Base64.encode(derCert));
        return cert_begin + pemCertPre + end_cert;
    }
}
