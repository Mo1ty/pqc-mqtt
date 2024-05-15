import com.mo1ty.mqtt.EncryptedPayload;
import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.crypto.AesUtil;
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

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class SecLv2PublisherApp {

    private static final String connectionUrl = "tcp://192.168.0.249:1883";
    private static final String connId = "RPI_ZERO_W_1";

    private static final String topic = "test/topic";
    private static final String initMessage = "INIT_CONN_2";
    private static final String responseTopic = "test/topic/response";

    private static final String aesKeyResponseTopic = "test/topic/aes/status";
    private static final String commMessage = "Communication message on level 2";

    private static CompletableFuture<PublicKey> publicKey = new CompletableFuture<>();
    private static CompletableFuture<String> aesKey = new CompletableFuture<>();

    private static final KyberClientUtil kyberClientUtil = new KyberClientUtil();

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

    public static void main(String[] args) throws Exception {

        System.out.println("INITIATING CONNECTION!");

        MqttAsyncClient client = createAndConnect(connectionUrl, connId);

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY MESSAGES
        System.out.println("CERTIFICATE INITIATED!");
        CertGen certGen = new CertGen();
        KeyPair falconKeyPair = certGen.generateKeyPair("Falcon", 1024);
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);
        System.out.println("CERTIFICATE DONE!");


        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        MessageStruct messageStruct = new MessageStruct(initMessage, topic);
        byte[] jsStr = messageStruct.toJsonStringAsBytes();
        byte[] signature = certGen.hashAndSignMessage(falconKeyPair, jsStr);
        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = signature;
        msgPayload.x509Certificate = certificate.getEncoded();

        System.out.println("CREATING JSON STRING AS BYTES!");
        String jsonData = msgPayload.toJsonString();
        System.out.println("PAYLOAD SET UP!");


        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY
        // SET PROPERTIES
        MqttMessage initialMessage = prepareQos2Message(jsonData);
        initialMessage.setProperties(new MqttProperties());
        initialMessage.getProperties().setResponseTopic(responseTopic);

        // RECEIVE A KYBER PUBLIC KEY FOR FURTHER COMMUNICATION
        KyberClientUtil kyberClientUtil = new KyberClientUtil();
        AesUtil aesUtil = new AesUtil();
        client.setCallback(new CustomMqttCallback());

        // SUBSCRIBE TO THE RESPONSE TOPIC
        // SEND THE INITIAL CONNECTION MESSAGE
        // WAIT UNTIL PUBLIC KEY IS RECEIVED
        System.out.println("SUBSCRIPTION TO THE RESPONSE TOPIC INITIATED");
        IMqttToken token = client.subscribe(responseTopic, 2);
        client.publish(topic, initialMessage);

        // GET PUBLIC KEY
        PublicKey pubKey = publicKey.get();
        SecretKey secretKey = aesUtil.generateAesKey();
        byte[] encryptedKey = kyberClientUtil.wrap(pubKey, secretKey);

        EncryptedPayload secretKeyPayload = new EncryptedPayload();
        secretKeyPayload.encryptedMessage = encryptedKey;
        secretKeyPayload.algorithmIdentifier = "kyber1024";
        secretKeyPayload.signature = certGen.hashAndSignMessage(falconKeyPair, encryptedKey);
        secretKeyPayload.x509Certificate = certificate.getEncoded();
        System.out.println("ENCRYPTED KEY ASSEMBLED INTO ENTITY, PREPARED AND READY TO SEND!");

        MqttMessage aesMessage = new MqttMessage();
        aesMessage.setQos(2);
        aesMessage.setPayload(secretKeyPayload.toJsonString().getBytes(StandardCharsets.UTF_8));
        aesMessage.setProperties(new MqttProperties());
        aesMessage.getProperties().setResponseTopic(aesKeyResponseTopic);

        System.out.println("SUBSCRIPTION TO THE RESPONSE TOPIC INITIATED");
        IMqttToken aesToken = client.subscribe(aesKeyResponseTopic, 2);
        aesToken.waitForCompletion();
        client.publish(topic, aesMessage).waitForCompletion();;
        System.out.println("SENT ENCRYPTED AES KEY!");

        System.out.println("Waiting for broker confirmation...");
        String aesSetup = aesKey.get();
        System.out.println("BROKER ACCEPTED AES KEY!");

        // SETUP TIMER TO SEND ENCRYPTED MESSAGES
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    MessageStruct msgStruct = new MessageStruct(commMessage, topic);
                    byte[] communicationStruct = msgStruct.toJsonStringAsBytes();
                    byte[] commSig = certGen.hashAndSignMessage(falconKeyPair, communicationStruct);
                    byte[] encryptedMessage = aesUtil.encrypt(secretKey, communicationStruct);
                    EncryptedPayload encryptedPayload = new EncryptedPayload(
                            encryptedMessage,
                            "AES",
                            commSig,
                            certificate.getEncoded()
                    );
                    System.out.println("PREPARED ENCRYPTED PAYLOAD!");

                    MqttMessage mqttMessage = new MqttMessage();
                    mqttMessage.setQos(2);
                    mqttMessage.setPayload(encryptedPayload.toJsonString().getBytes(StandardCharsets.UTF_8));
                    mqttMessage.setProperties(new MqttProperties());
                    client.publish(topic, mqttMessage);
                    System.out.println("SENT ENCRYPTED MESSAGE!");
                    System.out.println(encryptedPayload.toJsonString());

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 100000);

        System.out.println("INITIAL MESSAGE SENT!");
    }

    private static class CustomMqttCallback implements MqttCallback {
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
            if(topic.equals(responseTopic)){
                byte[] kyberKey = message.getPayload();
                Executors.newCachedThreadPool().submit(() -> {
                    publicKey.complete(kyberClientUtil.pubKeyFromBytes(kyberKey));
                    return null;
                });

                System.out.println("KYBER key received successfully!");
            }
            else if(topic.equals(aesKeyResponseTopic)){
                byte[] aesConfirm = message.getPayload();
                Executors.newCachedThreadPool().submit(() -> {
                    aesKey.complete(new String(aesConfirm, StandardCharsets.UTF_8));
                    return null;
                });

                System.out.println("RECEIVED AES CONFIRMATION FROM BROKER!");
            }
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
    }
}
