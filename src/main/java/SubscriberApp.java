import com.mo1ty.mqtt.subscriber.MqttSubscriber;
import com.mo1ty.utils.SignUtil;


public class SubscriberApp {

    public static void main(String[] args) throws InterruptedException {

        String connectionUrl = "tcp://192.168.0.208:1883";
        String connId = "PC_TEST";
        String topic = "test/topic";
        SignUtil signUtil = new SignUtil();

        MqttSubscriber client = new MqttSubscriber(connectionUrl, connId);
        client.connectClient();
        int i = 0;
        while(!client.getMqttClient().isConnected()){
            // Endless loop until connected;
            i++;
            System.out.println("Waiting for connection for " + i + " seconds...");
            Thread.sleep(1000);
            client.connectClient();
        }


    }

}
