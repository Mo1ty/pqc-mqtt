package com.mo1ty.mqtt.publisher;

import com.mo1ty.security.fulltrust.CertGen;
import org.eclipse.paho.mqttv5.client.*;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;

import java.nio.charset.StandardCharsets;


public class MqttPublisher {

    private static final String defaultTopic = "MQTT_Examples";
    private static final String testMessageContent = "Message from MqttPublishSample";
    private static final String defaultPublisherId = "JavaSample";


    private MemoryPersistence persistence;
    private MqttAsyncClient mqttClient;
    private MqttConnectionOptions mqttConnectionOptions;
    private String brokerUrl; // Example: "tcp://mqtt.eclipseprojects.io:1883"
    private String publisherId;
    private int qos = 2;

    public MqttPublisher(){
        this.persistence = new MemoryPersistence();
    }

    public MqttPublisher(String brokerUrl, String publisherId) {
        this.brokerUrl = brokerUrl;
        this.publisherId = publisherId;
        this.persistence = new MemoryPersistence();
        try{
            this.mqttClient = new MqttAsyncClient(brokerUrl, publisherId, persistence);
        }
        catch(MqttException me) {
            System.out.println("reason "+me.getReasonCode());
            System.out.println("msg "+me.getMessage());
            System.out.println("loc "+me.getLocalizedMessage());
            System.out.println("cause "+me.getCause());
            System.out.println("excep "+me);
            me.printStackTrace();
        }
    }

    public void connectClient() {
        try{
            if(mqttConnectionOptions == null)
                this.mqttClient.connect();
            else
                this.mqttClient.connect(mqttConnectionOptions);
        }
        catch(MqttException me) {
            System.out.println("reason "+me.getReasonCode());
            System.out.println("msg "+me.getMessage());
            System.out.println("loc "+me.getLocalizedMessage());
            System.out.println("cause "+me.getCause());
            System.out.println("excep "+me);
            me.printStackTrace();
        }
    }

    public void publishMessage(String topic, MqttMessage message) {
        try {
            this.mqttClient.publish(topic, message);
        }
        catch(MqttException me) {
            System.out.println("reason "+me.getReasonCode());
            System.out.println("msg "+me.getMessage());
            System.out.println("loc "+me.getLocalizedMessage());
            System.out.println("cause "+me.getCause());
            System.out.println("excep "+me);
            me.printStackTrace();
        }
    }

    public String getBrokerUrl() {
        return brokerUrl;
    }

    public void setBrokerUrl(String brokerUrl) {
        this.brokerUrl = brokerUrl;
    }

    public String getPublisherId() {
        return publisherId;
    }

    public void setPublisherId(String publisherId) {
        this.publisherId = publisherId;
    }

    public MemoryPersistence getPersistence() {
        return persistence;
    }

    public void setPersistence(MemoryPersistence persistence) {
        this.persistence = persistence;
    }

    public MqttAsyncClient getMqttClient() {
        return mqttClient;
    }

    public void setMqttClient(MqttAsyncClient mqttClient) {
        this.mqttClient = mqttClient;
    }

    public int getQos() {
        return qos;
    }

    public void setQos(int qos) {
        this.qos = qos;
    }

    public MqttConnectionOptions getMqttConnectionOptions() {
        return mqttConnectionOptions;
    }

    public void setMqttConnectionOptions(MqttConnectionOptions mqttConnectionOptions) {
        this.mqttConnectionOptions = mqttConnectionOptions;
    }
}
