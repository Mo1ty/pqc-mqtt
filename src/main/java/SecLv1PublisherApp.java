import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.fulltrust.CertGen;
import com.mo1ty.security.fulltrust.DummyGen;
import com.mo1ty.security.fulltrust.FalconGen;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttAsyncClient;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

public class SecLv1PublisherApp {

    private static final CertGen certGen = new FalconGen();
    private static final String connectionUrl = "tcp://192.168.0.249:1883";

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

    private static void sendMessage(String message, String topic, MqttAsyncClient client){
        try {
            client.publish(topic, prepareQos2Message(message));
            // System.out.println("Successfully published message \"" + message + "\" on topic \"" + topic + "\"!");

        } catch (Exception e) {
            e.printStackTrace();
        }
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

        String connId = "PC_PUB_LV1";
        String topic = "test/topic";
        String testMessage = RandomStringUtils.randomAlphanumeric(128);

        System.out.println(testMessage);

        MqttAsyncClient client = createAndConnect(connectionUrl, connId);

        // GENERATE A SELF-SIGNED CERTIFICATE TO SIGN AND VERIFY MESSAGES
        System.out.println("CERTIFICATE INITIATED!");
        KeyPair keyPair = certGen.generateKeyPair();
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(keyPair, certificateLength);
        System.out.println("CERTIFICATE DONE!");

        // SET UP MESSAGE PAYLOAD AND TRANSFORM INTO BYTE ARRAY TO SEND
        System.out.println("Connected successfully!");
        new Timer().schedule(new TimerTask() {
            public void run()  {
                try {
                    // Create message & start stopwatch
                    StopWatch stopWatch = new StopWatch();
                    stopWatch.start();

                    MessageStruct messageStruct = new MessageStruct(testMessage, topic);
                    byte[] signature = certGen.signMessage(keyPair, messageStruct.toJsonStringAsBytes());
                    MqttMsgPayload msgPayload = new MqttMsgPayload(
                            messageStruct,
                            signature,
                            certificate.getEncoded()
                    );
                    sendMessage(msgPayload.toJsonString(), topic, client);

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
