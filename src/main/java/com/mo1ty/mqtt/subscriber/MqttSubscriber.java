package com.mo1ty.mqtt.subscriber;

import org.eclipse.paho.mqttv5.client.*;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;

public class MqttSubscriber {

    private static final String defaultPublisherId = "JavaSample";


    private MemoryPersistence persistence;
    private MqttAsyncClient mqttClient;
    private MqttConnectionOptions mqttConnectionOptions;
    private String brokerUrl; // Example: "tcp://mqtt.eclipseprojects.io:1883"
    private String publisherId;
    private int qos = 2;

    public MqttSubscriber(){
        this.persistence = new MemoryPersistence();
    }

    public MqttSubscriber(String brokerUrl, String publisherId) {
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

    public MqttAsyncClient connectClient() {
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
        return mqttClient;
    }

    public IMqttToken subscribeToMessage(String topic) {
        MqttMessage mqttMessage = new MqttMessage();
        try {
            this.mqttClient.setCallback(new MqttCallback() {
                @Override
                public void disconnected(MqttDisconnectResponse disconnectResponse) {

                }

                @Override
                public void mqttErrorOccurred(MqttException exception) {

                }

                @Override
                public void messageArrived(String topic, MqttMessage message) throws Exception {
                    message = mqttMessage;
                }

                @Override
                public void deliveryComplete(IMqttToken token) {

                }

                @Override
                public void connectComplete(boolean reconnect, String serverURI) {

                }

                @Override
                public void authPacketArrived(int reasonCode, MqttProperties properties) {

                }
            });
            return this.mqttClient.subscribe(topic, 2);
        }
        catch(MqttException me) {
            System.out.println("reason "+me.getReasonCode());
            System.out.println("msg "+me.getMessage());
            System.out.println("loc "+me.getLocalizedMessage());
            System.out.println("cause "+me.getCause());
            System.out.println("excep "+me);
            me.printStackTrace();
        }
        return null;
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
