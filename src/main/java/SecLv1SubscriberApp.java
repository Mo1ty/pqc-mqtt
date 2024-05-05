import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.mqtt.publisher.MqttPublisher;
import com.mo1ty.mqtt.subscriber.MqttSubscriber;
import com.mo1ty.security.fulltrust.CertGen;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.paho.mqttv5.client.*;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class SecLv1SubscriberApp {


    public static void main(String[] args) throws Exception {

        String connectionUrl = "tcp://192.168.0.208:1883";
        String connId = "PC_TEST";
        String topic = "test/topic";
        String testMessage = "TEST_MESSAGE";


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
                byte[] jsonData = message.getPayload();

                MqttMsgPayload msg = MqttMsgPayload.getFromJsonString(jsonData);
                CertGen newCertGen = new CertGen();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(msg.x509Certificate);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(in);

                System.out.println("Message received successfully! Does signature work? - " + newCertGen.verifyHashedMessage(
                        cert.getPublicKey(),
                        msg.messageStruct.getBytes(),
                        Base64.decode(msg.signature)));
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

        mqttClient.connect();
        mqttClient.subscribe(topic, 2);

        int i = 0;
        while (mqttClient.isConnected()) {
            // Endless loop until connected;
        }
    }

}