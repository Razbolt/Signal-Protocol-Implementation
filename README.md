# Signal Protocol Implementation
- This is a term project for Cryptography CS 411 & CS 507 in Fall 2021, developed by E. Savas from the Computer Science & Engineering department at Sabanci University in Istanbul. The project aims to develop a simplified version of the Signal Protocol, which provides forward secrecy and deniability. The Signal Protocol is a practical cryptographic protocol, a variant of which is used in different applications such as WhatsApp.

## Project Phases
The project has three phases:

### Phase I: Developing software for the Public Key Registration
### Phase II: Developing software for receiving messages from other clients
### Phase III: Developing software to communicate with other clients
All development will be in the Python programming language.

## Getting Started
To connect to the university's VPN, if you are connecting from outside of the campus, please check the IT's website for OpenVPN access instructions.

## Prerequisites
Python programming language
NIST-256 elliptic curve (use "secp256k1" for the elliptic curve in your Python code)
## Installation
Clone the repository to your local machine.
### Phase I: Developing software for the Public Key Registration
In this phase of the project, you are required to upload one file: "Client.py". You will be provided with "Client basics.py", which includes all required communication codes.

#### Identity Key (IK)
Identity Key (IK) consists of a long-term public-private key pair, which each party generates once and uses to sign his/her SPK as shown in Section 2.2.

##### Registration of Identity Keys
The identity public key of the server IKS.Pub is given below.

X:93223115898197558905062012489877327981787036929201444813217704012422483432813
Y:8985629203225767185464920094198364255740987346743912071843303975587695337619

After generating your identity key pair, sign your ID (e.g., 18007) using the "Signature Generation" algorithm in Section 2.4.
Send a message containing your student ID, the signature tuple, and IKA.Pub to the server. A sample message is given in 'samples.txt'.
If your message is verified by the server successfully, you will receive an email, which includes your ID and a 6 digit verification code.
Send another message to the server to authenticate yourself. A sample message is given below.

{‘ID’: 18007, ‘CODE’: 209682}

If you send the correct verification code, you will receive an acknowledgement message via email, which states that you are registered with the server successfully and contains a code to reset your identity key if you need. (You must save the reset code to delete your IK from server, in case you need (e.g., your identity key is lost or compromised).)
##### Reseting your IK
If you lose your private identity key IKA.Pri, and need to reset your identity key pair, send a message to the server to delete your public identity key IKA.Pub from the server. The message format is "{'ID': stuID, 'RCODE': rcode}", where rcode is the reset code provided in the acknowledgement email. A sample message is as follows:


{‘ID’: 18007, ‘RCODE’: 209682}
If you lose the reset code, send an email to cs411tpserver@sabanciuniv.edu. Your IK will be deleted from the server after 8 hours.

##### Signed Pre-key (SPK)

###### .2.1 Registration of SPK
After you have registered your identity key, you are required to generate one pair of signed pre-key; SPKA.Pub and SPKA.Pri. Then, you must sign the public key part of the signed pre-key, SPKA.Pub using your identity key IKA. The signature, for which a scheme is given in Section 2.4, must be generated for the concatenated form of the public signed pre-key: (SPKA.Pub.x k SPKA.Pub.y).

Finally, you must send your signed pre-key to the server in the form of:


{'ID': stuID, 'SPKPUB.X': spkpub.x, 'SPKPUB.Y': spkpub.y, 'H': h, 'S': s}
where h and s denote the signature tuple. If your signed pre-key is registered successfully, the server will return its signed pre-key SPKS.Pub in the same format. After you check the validity of the signature of SPKS.Pub, you may use it.

###### 2.2.2 Reseting your SPK
If you lose your private signed pre-key SPKA.Pri, and need to reset your signed pre-key pair, you should sign your stuID using your identity key IKA and send a message to the server to delete your public identity key SPKA.Pub from the server. The message format is:


{'ID': stuID, 'H': h, 'S': s}


##### Registration of SPK

After registering your identity key, generate one pair of signed pre-key; SPKA.Pub and SPKA.Pri. Then, sign the public key part of the signed pre-key, SPKA.Pub using your identity key IKA. The signature, for which a scheme is given in Section 2.4, must be generated for the concatenated form of the public signed pre-key: (SPKA.Pub.x k SPKA.Pub.y). Finally, send your signed pre-key to the server in the form of:


{'ID': stuID , 'SPKPUB.X': spkpub.x, 'SPKPUB.Y': spkpub.y, 'H': h, 'S': s}
If your signed pre-key is registered successfully, the server will return its signed pre-key SPKS.Pub in the same format. After checking the validity of the signature of SPKS.Pub, you may use it.

###### Reseting your SPK
If you lose your private signed pre-key SPKA.Pri, and need to reset your signed pre-key pair, sign your stuID using your identity key IKA and send a message to the server to delete your public identity key SPKA.Pub from the server. The message format is:


{'ID': stuID, 'H': h, 'S': s}

###### One-time Pre-key (OTK)
One-time Pre-keys are the keys used to generate symmetric session keys in communication with other clients. Therefore, each client in the system must register his/her OTKs to the server before the communication.

###### Generating HMAC Key (KHMAC)
In the registration of OTKs, a hash-based MAC (HMAC) function will be used for authentication to provide deniability (instead of digital signature). Therefore, generate a symmetric HMAC Key (KHMAC) before the registration of OTKs. KHMAC will be computed as follows:


T = SPK A.Pri · SPK S.Pub
## Phase II: Developing software for receiving messages from other clients
To be continued in the next phase of the project.

## Contributing
If you would like to contribute to this project, please contact the developer which is me :)

## License
This project is licensed under the MIT License.

## Contact
For any questions or concerns regarding this project, please contact to erdemarslan@sabanciuniv.edu


- For more, you can find a detailed explanation under the Phase_3 pdf file which  gives all the details about the term project.

