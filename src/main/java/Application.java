import com.mo1ty.mqtt.publisher.MqttPublisher;
import com.mo1ty.security.fulltrust.CertGen;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

public class Application {
    private static MqttMessage prepareQos2Message(String messageText){
        MqttMessage msg = new MqttMessage();
        msg.setQos(2);
        msg.setPayload(messageText.getBytes());
        return msg;
    }

    public static void main(String[] args) {

        CertGen certGen = new CertGen();

        String text = "Hello, this is me, the basic text";
        byte[] plaintext = text.getBytes(StandardCharsets.UTF_8);

        try{
            KeyPair falconKeyPair = certGen.generateKeyPair("Falcon", 1024);
            Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
            X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);

            byte[] signature = certGen.hashAndSignMessage(certificate, falconKeyPair, plaintext);

            System.out.println(certGen.verifyMessage(falconKeyPair.getPublic(), plaintext, signature));
            System.out.println(certGen.verifyHashedMessage(falconKeyPair.getPublic(), plaintext, signature));
        }
        catch (Exception e){
            e.printStackTrace();
        }









        /*
        String connectionUrl = "tcp://192.168.0.208:1883";
        String connId = "PC_TEST";
        String topic = "test/topic";

        MqttPublisher client = new MqttPublisher(connectionUrl, connId);
        client.connectClient();
        while(!client.getMqttClient().isConnected()){
            // Endless loop until connected;
            System.out.println("Not connected yet!");
            Thread.sleep(2500);
            client.connectClient();
            continue;
        }
        System.out.println("Connected successfully!");
        Random rand = new Random();
        new Timer().schedule(new TimerTask() {
            public void run()  {
                String number = String.valueOf(rand.nextInt(100));
                client.publishMessage(topic, prepareQos2Message(number));
                System.out.println("Successfully published message \"" + number + "\" on topic \"" + topic + "\"!");
            }
        }, 1, 1);


        System.out.println("Message sent!");
        */
    }
}
