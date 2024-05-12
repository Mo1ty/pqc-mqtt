import com.mo1ty.mqtt.EncryptedPayload;
import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.crypto.KyberClientUtil;
import com.mo1ty.security.fulltrust.CertGen;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttAsyncClient;
import org.eclipse.paho.mqttv5.client.MqttCallback;
import org.eclipse.paho.mqttv5.client.MqttDisconnectResponse;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;
import org.eclipse.paho.mqttv5.common.packet.UserProperty;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Timer;
import java.util.TimerTask;

public class SecLv2PublisherApp {
    private static MqttMessage prepareQos2Message(String messageText){
        MqttMessage msg = new MqttMessage();
        msg.setQos(2);
        msg.setPayload(messageText.getBytes(StandardCharsets.UTF_8));
        return msg;
    }

    private static MqttAsyncClient createAndConnect(String connectionUrl, String connectionId) throws Exception{
        MqttAsyncClient client = new MqttAsyncClient(connectionUrl, connectionId, new MemoryPersistence());
        IMqttToken token = client.connect();
        token.waitForCompletion();
        return client;
    }

    private static String payloadToJsonString(String message, String topic, String algorithmIdentifier) throws Exception{
        MessageStruct messageStruct = new MessageStruct(message, topic);

        EncryptedPayload payload = new EncryptedPayload();
        payload.encryptedMessage = message;
        payload.algorithmIdentifier = algorithmIdentifier;
        return payload.toJsonString();
    }

    private static void sendMessage(String message, String topic, MqttAsyncClient client){
        try {
            client.publish(topic, prepareQos2Message(message)).waitForCompletion();
            System.out.println("Successfully published message \"" + message + "\" on topic \"" + topic + "\"!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

        String connectionUrl = "tcp://192.168.0.208:1883";
        String connId = "PC_TEST_PUB_2";
        String topic = "test/topic";
        String testMessage = "INIT_CONN_2";
        String responseTopic = "test/topic/response";
        String deviceIdentifier = "RPI_ZERO_W_1";

        MqttAsyncClient client = createAndConnect(connectionUrl, connId);

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY INITIAL MESSAGE
        CertGen certGen = new CertGen();
        KeyPair falconKeyPair = certGen.generateKeyPair("Falcon", 1024);
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);


        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        MessageStruct messageStruct = new MessageStruct(testMessage, topic);
        byte[] signature = certGen.hashAndSignMessage(falconKeyPair, messageStruct.toJsonStringAsBytes());
        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = Base64.encode(signature);
        msgPayload.x509Certificate = certificate.getEncoded();
        String jsonData = msgPayload.toJsonString();
        MqttMessage initialMessage = prepareQos2Message(jsonData);
        initialMessage.getProperties().setResponseTopic(responseTopic);
        initialMessage.getProperties().getUserProperties().add(new UserProperty("DEVICE_IDENTIFIER", deviceIdentifier));


        // RECEIVE A KYBER PUBLIC KEY FOR FURTHER COMMUNICATION
        KyberClientUtil kyberClientUtil = new KyberClientUtil();
        client.setCallback(new MqttCallback() {
            @Override
            public void disconnected(MqttDisconnectResponse disconnectResponse) {
                System.out.println("DISCONNECTED FROM BROKER. FINISHING PROGRAM!");
                System.exit(0);
            }

            @Override
            public void mqttErrorOccurred(MqttException exception) {
                System.out.println("##################### MQTT ERROR OCCURRED DURING THE EXECUTION ######################");
                System.out.println(exception.getMessage());
                System.out.println("##################### SHUTTING THE PROGRAM DOWN ######################");
                System.exit(1);
            }

            @Override
            public void messageArrived(String topic, MqttMessage message) throws Exception {
                byte[] kyberKeyInfo = message.getPayload();
                kyberClientUtil.pubKeyFromBytes(kyberKeyInfo);
                System.out.println("Key received successfully!");
            }

            @Override
            public void deliveryComplete(IMqttToken token) {

            }

            @Override
            public void connectComplete(boolean reconnect, String serverURI) {
                System.out.println("CONNECTION SUCCESSFUL! CONNECTED TO THE BROKER - " + serverURI);
            }

            @Override
            public void authPacketArrived(int reasonCode, MqttProperties properties) {

            }
        });
        client.subscribe(topic, 2).waitForCompletion();

        // SETUP TIMER TO SEND ENCRYPTED MESSAGES
        System.out.println("Connected successfully!");
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    String messageBytes = payloadToJsonString(testMessage, topic, "Kyber-1024");
                    sendMessage(messageBytes, topic, client);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 100);

        System.out.println("INITIAL MESSAGE SENT!");
    }

    static String encodeCert(X509Certificate certificate) throws Exception {
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";
        byte[] derCert = certificate.getEncoded();
        String pemCertPre = new String(Base64.encode(derCert));
        return cert_begin + pemCertPre + end_cert;
    }
}
