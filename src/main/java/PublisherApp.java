import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.mqtt.publisher.MqttPublisher;
import com.mo1ty.security.fulltrust.CertGen;
import org.bouncycastle.cert.X509CertificateHolder;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

public class PublisherApp {
    private static MqttMessage prepareQos2Message(String messageText){
        MqttMessage msg = new MqttMessage();
        msg.setQos(2);
        msg.setPayload(messageText.getBytes());
        return msg;
    }

    public static void main(String[] args) throws Exception {

        String connectionUrl = "tcp://192.168.0.208:1883";
        String connId = "PC_TEST";
        String topic = "test/topic";
        CertGen certGen = new CertGen();

        MqttPublisher client = new MqttPublisher(connectionUrl, connId);
        client.connectClient();
        int i = 0;
        while(!client.getMqttClient().isConnected()){
            // Endless loop until connected;
            i++;
            System.out.println("Waiting for connection for " + i + " seconds...");
            Thread.sleep(1000);
            client.connectClient();
        }

        KeyPair falconKeyPair = certGen.generateKeyPair("Falcon", 1024);
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);

        System.out.println("Connected successfully!");
        Random rand = new Random();
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    String number = String.valueOf(rand.nextInt(100));
                    MessageStruct messageStruct = new MessageStruct(number, topic);
                    byte[] signature = certGen.hashAndSignMessage(falconKeyPair, messageStruct.getBytes());

                    MqttMsgPayload msgPayload = new MqttMsgPayload();
                    msgPayload.messageStruct = messageStruct;
                    msgPayload.signature = signature;
                    msgPayload.x509Certificate = certificate;

                    client.publishMessage(topic, prepareQos2Message(number));
                    System.out.println("Successfully published message \"" + number + "\" on topic \"" + topic + "\"!");

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 100);


        System.out.println("Message sent!");
    }
}
