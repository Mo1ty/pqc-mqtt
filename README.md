# pqc-mqtt

Post-quantum MQTT client - an MQTT client application based on Eclipse Paho client, using Bouncy Castle for encryption.
Requires broker for communication. For example, pqc-mqtt-broker contains compatible broker implementation.

## How to launch
This application requires Java 8 to work. Before start, it is important to open the main classes of the publisher and subscriber and set the connection URL address and "certGen" algorithm entity matching the IP address and algorithm used in broker respectively.

build.gradle file contains 4 different tasks that can be used to build a fatJar archives of publishers and subscribers on required levels. 

It is strongly advised to start subscriber before the publisher, otherwise data sent by publisher may be lost.

## Shortly about security
This application is capable of communication on two levels of security: 
1) First level utilizes message signatures. Publisher will sign the message before sending to the subscribers, which will verify the signature. Algorithms supported are Falcon and Dilithium. (only one is usable at time) 
2) Second level requires handshake for clients to connect properly. Without the handshake, it is not possible to agree on AES keys and therefore broker will block any packet sent by client and any attenpt to retrieve one by subscriber.
