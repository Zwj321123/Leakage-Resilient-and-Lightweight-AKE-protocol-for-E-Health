# Leakage-Resilient-and-Lightweight-AKE-protocol-for-E-Health
E-Health is the use of information and communication technologies for health care. It becomes popular in recent years. Since user identities and health data are generally involved, information security and privacy have been constituting signiﬁcant problems in E-Health applications. To protect sensitive health data and identity information, many international communication standards suitable for E-Health applications provide authenticated key exchange (AKE) protocols as security foundations in their latest versions of technical standards or speciﬁcations. An AKE protocol can establish a freshly shared secret key among communicating devices in E-Health applications. The shared key will be used to encrypt message ﬂows including registration or logon information or medical data. For example, the international standard for wireless body area network, IEEE 802.15.6 [1], provides a serials of authenticated association protocols. These protocols are AKE protocols which can establish shared secret keys for medical sensor nodes and their coordinators. Another widely adopted communication technique, the Bluetooth wireless network, also introduces a group of secure simple pairing protocols in its latest version Bluetooth Speciﬁcation 5.0 [2]. The secure simple pairing protocols are essentially AKE protocols to establish shared secret keys for two devices connected by Bluetooth networks. 

In this project, a leakage-resilient and lightweight (LLR) ECDH-based authenticated key exchange (AKE) protocol is proposed. It applies the Blind Scheme [3] to hind the long-term secrets in computations. As a result, the timing or power consumed by computations is randomized in different runs of the protocol. Second, to make the proposed protocol more friendly to capability-limited medical sensor, we alleviate the computational burden on the limited side by transferring some time-consuming operations to its communicating partner which is usually a more powerful coordinator or gateway. Finally, we also realize prototypes of the proposed lightweight and leakage-resilient (LLR) AKE protocol, and the similar protocols in IEEE 802.15.6 (denoted as IEEE protocol) and Bluetooth 5.0 (denoted as Bluetooth protocol). Based on the prototypes, a series of experiments are carried out to evaluate and compare the performance. According to the experiment results, the proposed leakage-resilient AKE protocols are more friendly to limited devices.

The prototypes of the LLR-AKE protocol, Bluetooth Display protocol and IEEE Display protocol are simulated in Python programing language. The initiator A can be deployed on either a virtual machine or a Raspberry Pi and responder B is deployed on a laptop.

Codes for node A (sensor):
----------------------------------------------------------------------------------------
-LLR AKE protocol: 
 protocol5a-A0.PY
 secret_code.PY (code that implements the Blind Scheme)
 getCPU.py (examine CPU usage during the scalar multiplication, optional)
 storageA.txt (update or refresh the permanent secret key after each computation round)

-Bluetooth protocol(banchmark):
  r5bluetoothA.py

-IEEE protocol(banchmark):
  r5bandisplaysensor.py
 
 Codes for node B (coordinator):
 ----------------------------------------------------------------------------------------
 -LLR AKE protocol: 
  protocol5a-B0.PY
  secret_code.PY (code that implements the Blind Scheme)
  getCPU.py (examine CPU usage during the scalar multiplication, optional)
  storage.txt (update or refresh the permanent secret key after each computation round)
  
-Bluetooth protocol(banchmark):
  r5bluetoothB.py

-IEEE protocol(banchmark):
  r5bandisplaycoor.py
  
References
------------------------------------------------------------------------------------------
[1] IEEE Computer Society, IEEE Standard for Local and Metropolitan Area Networks - Part 15.6: Wireless Body Area Networks. 2012. 
[2] Bluetooth SIG Proprietary, Bluetooth Core Speciﬁcation, version 5.0. 2019. 
[3] E. Kiltz, and K. Pietrzak, Leakage Resilient ElGamal Encryption. Advances in Cryptology-ASIACRYPT 2010. Lecture Notes in Computer Science, Vol. 6477, Springer, Berlin, Heidelberg 634-646, 2010. 
