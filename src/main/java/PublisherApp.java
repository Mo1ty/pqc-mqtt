import com.mo1ty.mqtt.MessageStruct;
import com.mo1ty.mqtt.MqttMsgPayload;
import com.mo1ty.security.cert.SignUtil;
import com.mo1ty.security.cert.CertificateGenerator;
import com.mo1ty.security.cert.FalconCertificateGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;

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
        SignUtil signUtil = new SignUtil();

        /*
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
        */

        CertificateGenerator certGen = new FalconCertificateGenerator();

        KeyPair falconKeyPair = certGen.generateKeyPair();
        Long certificateLength = 6 * 24 * 60 * 60 * 1000L; // 6 days
        X509Certificate certificate = certGen.genSelfSignedCert(falconKeyPair, certificateLength);

        Random rand = new Random();

        String number = String.valueOf(rand.nextInt(100));
        MessageStruct messageStruct = new MessageStruct(number, topic);
        byte[] signature = signUtil.hashAndSignMessage(falconKeyPair, messageStruct.getBytes());

        MqttMsgPayload msgPayload = new MqttMsgPayload();
        msgPayload.messageStruct = messageStruct;
        msgPayload.signature = Base64.encode(signature);
        msgPayload.x509Certificate = Base64.encode(certificate.getEncoded());

        // byte[] jsonData = msgPayload.toJsonString().getBytes(StandardCharsets.UTF_8);




        File file = new File("C:/Users/Mo1ty/Desktop/totalFile_encoded.txt");
        BufferedWriter writer = new BufferedWriter(new FileWriter(file));
        writer.write(Arrays.toString(msgPayload.encodeInfo()));
        writer.close();





        MqttMsgPayload msg = new MqttMsgPayload(); // = MqttMsgPayload.getFromJsonString(jsonData);

        SignUtil newCertGen = new SignUtil();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(msg.x509Certificate);
        X509Certificate cert = (X509Certificate)cf.generateCertificate(in);

        System.out.println(newCertGen.verifyHashedMessage(
                cert.getPublicKey(),
                msg.messageStruct.getBytes(),
                msg.signature));

        /*
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

                    byte[] jsonData = msgPayload.toJsonString().getBytes(StandardCharsets.UTF_8);

                    System.out.println(jsonData);

                    client.publishMessage(topic, prepareQos2Message(number));
                    System.out.println("Successfully published message \"" + number + "\" on topic \"" + topic + "\"!");

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 0, 100);

         */

        System.out.println("Message sent!");
    }

    static void writeCertToFileBase64Encoded(X509Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }
}
