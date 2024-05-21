import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.fulltrust.CertGen;
import com.mo1ty.security.fulltrust.FalconGen;
import org.apache.commons.lang3.time.StopWatch;
import org.eclipse.paho.mqttv5.client.*;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;


public class SecLv1SubscriberApp {

    private static final CertGen certGen = new FalconGen();
    private static final String connectionUrl = "tcp://192.168.0.249:1883";

    private static int packetNum = -100;
    private static List<Double> packetTimes = new ArrayList<>();

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
        String connId = "PC_SUB_LV1";
        String topic = "test/topic";

        MqttAsyncClient mqttClient = new MqttAsyncClient(connectionUrl, connId, new MemoryPersistence());
        mqttClient.setCallback(new MqttCallback() {
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
                StopWatch stopWatch = new StopWatch();
                stopWatch.start();

                byte[] jsonData = message.getPayload();
                MqttMsgPayload msg = MqttMsgPayload.getFromJsonString(jsonData);

                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(msg.x509Certificate);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                boolean isVerified = certGen.verifyMessage(cert.getPublicKey(), msg.messageStruct.toJsonStringAsBytes(), msg.signature);

                stopWatch.stop();

                double time = stopWatch.getNanoTime();
                time /= 1000000L;
                if(!isVerified){
                    throw new Exception("Signature is not valid!");
                }
                System.out.println("Milliseconds required for packet to prepare and be sent: " + time);
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

        mqttClient.connect().waitForCompletion();
        mqttClient.subscribe(topic, 2);

        int i = 0;
        while (mqttClient.isConnected()) {
            // Endless loop until connected;
        }
    }

}
