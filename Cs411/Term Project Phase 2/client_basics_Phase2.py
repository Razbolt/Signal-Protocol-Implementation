import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://10.92.52.175:5000/'

stuID =  23813  ## Change this to your ID number
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator
curve = E

#my public private key generation
random.seed(68)
secretkey = random.randint(0, E.order-2)
Qa = secretkey*P # my public key
print("Q on curve?", E.is_on_curve(Qa))

# signature generation for my ID
random.seed(37)
k = random.randint(0, E.order-3)
R = k*P
lower_r = (R.x) % n
msg = stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big')
hashdata = lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big') + msg
h_object = SHA3_256.new()
h_object.update(data=hashdata)

h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
s = (k - (secretkey*int.from_bytes(h_object.digest(), byteorder='big'))) % n

ikpubx = Qa.x
ikpuby = Qa.y
#server's Identitiy public key
IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

#Send Public Identitiy Key Coordinates and corresponding signature
def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

#Send the verification code
def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

#Send SPK Coordinates and corresponding signature
def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

#Send OTK Coordinates and corresponding hmac
def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
#Reset Code is sent when you first registered
def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

#Send the reset code to delete your Identitiy Key
def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#get your messages. server will send 1 message from your inbox 
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())





#getting 5 messages
PseudoSendMsg(h, s)

key_dict = [None] * 10
for i in range(0, 10):

	random.seed(200 + i)
	otk_secret = random.randint(0, E.order-2) 
	otk_pub = otk_secret*P
	otk_pub_x = otk_pub.x
	otk_pub_y = otk_pub.y
	key_dict[i] = {'otk_secret': otk_secret, 'otk_pub_x': otk_pub_x, 'otk_pub_x': otk_pub_x}



ID_b, OTK_id, MSG_id, MSG, EK_x, EK_y = ReqMsg(h, s)
print("ID_B: ", ID_b)
print("OTK_id: ", OTK_id)
print("MSG_id: ", MSG_id)
print("MSG: ", MSG)
print("EK_x: ", EK_x)
print("EK_y: ", EK_y)
print("**************************************************************")
print("**************************************************************")

#session key generation
EK_PUB = Point(EK_x ,EK_y, curve)
OTKA = key_dict[0]['otk_secret']
T = OTKA*EK_PUB
T_x = T.x
T_y = T.y
U = T_x.to_bytes((T_x.bit_length()+7)//8, byteorder='big') + T_y.to_bytes((T_y.bit_length()+7)//8, byteorder='big') + b'MadMadWorld'
k_session = SHA3_256.new()
k_session.update(data=U)

#KDF CHAIN
k_enc = SHA3_256.new()
u_data = k_session.digest() + b'LeaveMeAlone'
k_enc.update(data=u_data)

k_hmac = SHA3_256.new()
u_data = k_enc.digest() + b'GlovesAndSteeringWheel'
k_hmac.update(data=u_data)

array_msg = MSG.to_bytes((MSG.bit_length()+7)//8, byteorder='big')
mac_value = array_msg[-32:]

s_cipher = AES.new(k_enc.digest(), AES.MODE_CTR, nonce=array_msg[0:8])
plaintext = s_cipher.decrypt(array_msg[8:-32])
print("plaintext: ", plaintext)
print("decoded plaintext: ", str(plaintext.decode('ISO-8859-1')))

# = ciphertext[8:-32]









