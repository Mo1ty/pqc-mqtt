import com.mo1ty.mqtt.EncryptedPayload;
import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.crypto.AesUtil;
import com.mo1ty.security.crypto.KyberClientUtil;
import com.mo1ty.security.fulltrust.CertGen;
import com.mo1ty.security.fulltrust.DummyGen;
import org.apache.commons.lang3.time.StopWatch;
import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttAsyncClient;
import org.eclipse.paho.mqttv5.client.MqttCallback;
import org.eclipse.paho.mqttv5.client.MqttDisconnectResponse;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

public class SecLv2SubscriberApp {

    private static final String initMessage = "INIT_CONN_2";

    private static final String initTopic = "test/init/topic";
    private static final String initResponseTopic = "test/init/topic/response";

    private static final String aesKeyResponseTopic = "test/init/topic/aes/status";

    private static int packetNum = -100;
    private static List<Double> packetTimes = new ArrayList<>();

    private static CompletableFuture<PublicKey> publicKey = new CompletableFuture<>();
    private static CompletableFuture<String> aesKey = new CompletableFuture<>();

    private static final CertGen certGen = new DummyGen();
    private static final KyberClientUtil kyberClientUtil = new KyberClientUtil();
    private static final AesUtil aesUtil = new AesUtil();

    private static MqttAsyncClient createAndConnect(String connectionUrl, String connectionId) throws Exception{
        MqttAsyncClient client = new MqttAsyncClient(connectionUrl, connectionId, new MemoryPersistence());
        System.out.println("CONNECTION INITIATED!");
        IMqttToken token = client.connect();
        token.waitForCompletion();
        System.out.println("CLIENT CONNECTED!");
        return client;
    }

    private static MqttMessage prepareQos2Message(String messageText){
        MqttMessage msg = new MqttMessage();
        msg.setQos(2);
        msg.setPayload(messageText.getBytes(StandardCharsets.UTF_8));
        return msg;
    }

    private static void countAvg(){
        double packetTimeTotal = 0;
        List<Double> packetTime1percent = new ArrayList<>(10);
        double packetTimeWorst = 0;
        for(int i = 0; i < packetTimes.size(); i++){
            int div = i / 50;
            int mod = i % 50;
            double currentPacketTime = packetTimes.get(i);

            if(mod == 0){
                packetTime1percent.add(div, 0.0);
            }

            packetTimeTotal += currentPacketTime;

            System.out.println(div);
            if(currentPacketTime > packetTime1percent.get(div))
                packetTime1percent.add(div, currentPacketTime);
            if(currentPacketTime > packetTimeWorst){
                packetTimeWorst = currentPacketTime;
            }

        }
        double packetTime1percentAvg = 0.0;
        for(int i = 0; i < packetTime1percent.size(); i++){
            packetTime1percentAvg += packetTime1percent.get(i);
        }

        System.out.println("All packets sent! " +
                "\n Average time: " + packetTimeTotal / packetTimes.size() +
                "\n Average 1% time: " + packetTime1percentAvg / packetTime1percent.size() +
                "\n Worst packet time: " + packetTimeWorst);
    }

    public static void main(String[] args) throws Exception {
        String connectionUrl = "tcp://192.168.0.249:1883";
        String connId = "RPI_MODEL_1_B";
        String topic = "test/topic";

        System.out.println("INITIATING CONNECTION!");

        MqttAsyncClient client = createAndConnect(connectionUrl, connId);

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY MESSAGES
        System.out.println("CERTIFICATE INITIATED!");
        KeyPair keyPair = certGen.generateKeyPair("dummy");
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(keyPair, certificateLength);
        System.out.println("CERTIFICATE DONE!");

        // Set up timer to start counting
        System.out.println(System.currentTimeMillis());
        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        MessageStruct messageStruct = new MessageStruct(initMessage, initTopic);
        byte[] jsStr = messageStruct.toJsonStringAsBytes();
        byte[] signature = certGen.signMessage(keyPair, jsStr);
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
        initialMessage.getProperties().setResponseTopic(initResponseTopic);

        // RECEIVE A KYBER PUBLIC KEY FOR FURTHER COMMUNICATION
        client.setCallback(new AuthMqttCallback());

        // SUBSCRIBE TO THE RESPONSE TOPIC
        // SEND THE INITIAL CONNECTION MESSAGE
        // WAIT UNTIL PUBLIC KEY IS RECEIVED
        System.out.println("SUBSCRIPTION TO THE RESPONSE TOPIC INITIATED");
        client.subscribe(initResponseTopic, 2);
        client.publish(initTopic, initialMessage);

        // GET PUBLIC KEY
        PublicKey pubKey = publicKey.get();
        final SecretKey secretKey = aesUtil.generateAesKey();
        byte[] encryptedKey = kyberClientUtil.wrap(pubKey, secretKey);

        EncryptedPayload secretKeyPayload = new EncryptedPayload();
        secretKeyPayload.encryptedMessage = encryptedKey;
        secretKeyPayload.algorithmIdentifier = "kyber1024";
        secretKeyPayload.signature = certGen.signMessage(keyPair, encryptedKey);
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
        client.publish(topic, aesMessage).waitForCompletion();
        System.out.println("SENT ENCRYPTED AES KEY!");

        System.out.println("Waiting for broker confirmation...");
        String aesConfirm = aesKey.get();
        System.out.println("BROKER ACCEPTED AES KEY!");


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
                // Start stopwatch
                StopWatch stopWatch = new StopWatch();
                stopWatch.start();

                byte[] jsonData = message.getPayload();
                EncryptedPayload encryptedPayload = EncryptedPayload.getFromJsonString(jsonData);

                // Validate payload using certificate
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(encryptedPayload.x509Certificate);
                X509Certificate encryptedCert = (X509Certificate) cf.generateCertificate(in);

                boolean isSignatureValid = certGen.verifyMessage(encryptedCert.getPublicKey(), aesUtil.decrypt(secretKey, encryptedPayload.encryptedMessage), encryptedPayload.signature);
                if(!isSignatureValid)
                    throw new Exception("Signature is not valid!");


                // decrypt payload and create entity for publish
                byte[] plainMessage = aesUtil.decrypt(secretKey, encryptedPayload.encryptedMessage);
                MessageStruct messageStruct = MessageStruct.getFromBytes(plainMessage);
                System.out.println(messageStruct.plainMessage);

                stopWatch.stop();

                double time = stopWatch.getNanoTime();
                time /= 1000000L;
                System.out.println("Is signature valid: " + isSignatureValid + ". Milliseconds required for packet to be decrypted and verified: " + time);
                packetNum++;
                if(packetNum > 0)
                    packetTimes.add(time);
                if (packetNum == 500){
                    countAvg();
                    System.exit(0);
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
        });
        client.subscribe(topic, 2);

        int i = 0;
        while (client.isConnected()) {
            // Endless loop until connected;
        }
    }

    private static class AuthMqttCallback implements MqttCallback {
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
        public void messageArrived(String topic, MqttMessage message) {
            if(topic.equals(initResponseTopic)){
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
