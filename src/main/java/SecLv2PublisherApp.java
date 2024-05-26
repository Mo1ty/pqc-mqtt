import com.mo1ty.mqtt.EncryptedPayload;
import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.crypto.AesUtil;
import com.mo1ty.security.crypto.KyberClientUtil;
import com.mo1ty.security.fulltrust.CertGen;
import com.mo1ty.security.fulltrust.FalconGen;
import org.apache.commons.lang3.RandomStringUtils;
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
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

public class SecLv2PublisherApp {

    private static final CertGen certGen = new FalconGen();
    private static final String connectionUrl = "tcp://192.168.0.249:1883";

    private static final String connId = "RPI_ZERO_W_1";

    private static final String topic = "test/topic";
    private static final String initMessage = "INIT_CONN_2";
    private static final String responseTopic = "test/topic/response";

    private static final String aesKeyResponseTopic = "test/topic/aes/status";
    private static String commMessage = "Communication message on level 2";

    private static CompletableFuture<PublicKey> publicKey = new CompletableFuture<>();
    private static CompletableFuture<String> aesKey = new CompletableFuture<>();

    private static final KyberClientUtil kyberClientUtil = new KyberClientUtil();

    private static int packetNum = -100;
    private static List<Double> packetTimes = new ArrayList<>();

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

        commMessage = RandomStringUtils.randomAlphanumeric(1024);
        System.out.println(commMessage);

        StopWatch initStopWatch = new StopWatch();
        initStopWatch.start();

        System.out.println("INITIATING CONNECTION!");

        MqttAsyncClient client = createAndConnect(connectionUrl, connId);

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY MESSAGES
        System.out.println("CERTIFICATE INITIATED!");
        KeyPair keyPair = certGen.generateKeyPair();
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(keyPair, certificateLength);
        System.out.println("CERTIFICATE DONE!");

        // Set up timer to start counting
        System.out.println(System.currentTimeMillis());
        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        MessageStruct messageStruct = new MessageStruct(initMessage, topic);
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
        initialMessage.getProperties().setResponseTopic(responseTopic);

        // RECEIVE A KYBER PUBLIC KEY FOR FURTHER COMMUNICATION
        KyberClientUtil kyberClientUtil = new KyberClientUtil();
        AesUtil aesUtil = new AesUtil();
        client.setCallback(new CustomMqttCallback());

        // SUBSCRIBE TO THE RESPONSE TOPIC
        // SEND THE INITIAL CONNECTION MESSAGE
        // WAIT UNTIL PUBLIC KEY IS RECEIVED
        System.out.println("SUBSCRIPTION TO THE RESPONSE TOPIC INITIATED");
        client.subscribe(responseTopic, 2);
        client.publish(topic, initialMessage);

        // GET PUBLIC KEY
        PublicKey pubKey = publicKey.get();
        SecretKey secretKey = aesUtil.generateAesKey();
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

        // Finish time count to see connection time needed
        initStopWatch.stop();
        double time = initStopWatch.getNanoTime();
        time /= 1000000L;
        System.out.println("Milliseconds required for connection to be established: " + time);

        // SETUP TIMER TO SEND ENCRYPTED MESSAGES
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    // Create message & start stopwatch
                    StopWatch stopWatch = new StopWatch();
                    stopWatch.start();

                    MessageStruct msgStruct = new MessageStruct(commMessage, topic);
                    byte[] communicationStruct = msgStruct.toJsonStringAsBytes();
                    byte[] commSig = certGen.signMessage(keyPair, communicationStruct);
                    byte[] encryptedMessage = aesUtil.encrypt(secretKey, communicationStruct);
                    EncryptedPayload encryptedPayload = new EncryptedPayload(
                            encryptedMessage,
                            "AES",
                            commSig,
                            certificate.getEncoded()
                    );

                    MqttMessage mqttMessage = new MqttMessage();
                    mqttMessage.setQos(2);
                    mqttMessage.setPayload(encryptedPayload.toJsonString().getBytes(StandardCharsets.UTF_8));
                    mqttMessage.setProperties(new MqttProperties());
                    client.publish(topic, mqttMessage);

                    // Stop the stopwatch. Print time it measured.
                    stopWatch.stop();
                    double time = stopWatch.getNanoTime();
                    time /= 1000000L;
                    System.out.println("Milliseconds required for packet to prepare and be sent: " + time);
                    packetNum++;
                    if(packetNum > 0)
                        packetTimes.add(time);
                    if (packetNum == 500){
                        countAvg();
                        System.exit(0);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 750);

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
        public void messageArrived(String topic, MqttMessage message) {
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
