import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.mqtt.publisher.MqttPublisher;
import com.mo1ty.security.fulltrust.CertGen;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SecLv2PublisherApp {
    private static MqttMessage prepareQos2Message(String messageText){
        MqttMessage msg = new MqttMessage();
        msg.setQos(2);
        msg.setPayload(messageText.getBytes());
        return msg;
    }

    private static MqttPublisher createAndConnect(String connectionUrl, String connectionId) throws Exception{
        MqttPublisher client = new MqttPublisher(connectionUrl, connectionId);
        client.connectClient();
        int i = 0;
        while(!client.getMqttClient().isConnected()){
            // Endless loop until connected;
            i++;
            System.out.println("Waiting for connection for " + i + " seconds...");
            Thread.sleep(1000);
            client.connectClient();
        }

        return client;
    }

    private static byte[] payloadToBytes(String message, String topic, CertGen certGen, KeyPair falconKeyPair, byte[] certificate) throws Exception{
        MessageStruct messageStruct = new MessageStruct(message, topic);
        byte[] signature = certGen.hashAndSignMessage(falconKeyPair, messageStruct.getBytes());

        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = signature;
        msgPayload.x509Certificate = certificate;

        return msgPayload.toJsonString().getBytes(StandardCharsets.UTF_8);
    }

    private static void sendMessage(String message, String topic, MqttPublisher client){
        try {
            client.publishMessage(topic, prepareQos2Message(message));
            System.out.println("Successfully published message \"" + message + "\" on topic \"" + topic + "\"!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        String connectionUrl = "tcp://192.168.0.208:1883";
        String connId = "PC_TEST";
        String topic = "test/topic";
        String testMessage = "TEST_MESSAGE";

        /*
        MqttPublisher client = createAndConnect(connectionUrl, connId);
        */

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY MESSAGES
        CertGen certGen = new CertGen();
        KeyPair falconKeyPair = certGen.generateKeyPair("Falcon", 1024);
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);

        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        MessageStruct messageStruct = new MessageStruct(testMessage, topic);
        byte[] signature = certGen.hashAndSignMessage(falconKeyPair, messageStruct.getBytes());
        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = Base64.encode(signature);
        msgPayload.x509Certificate = certificate.getEncoded();
        byte[] jsonData = msgPayload.toJsonString().getBytes(StandardCharsets.UTF_8);

        /*
        System.out.println("Connected successfully!");
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    byte[] messageBytes = payloadToBytes(testMessage, topic, certGen, falconKeyPair, certificate.getEncoded());
                    sendMessage(messageBytes, topic, client);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 100);
        */


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
