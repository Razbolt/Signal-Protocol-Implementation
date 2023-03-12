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

stuID = 23813  #type your stu id

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


'''
{'ID': 23813, 'H': 107286773202286475954448646888056649328711995751140402491323606062425844552020, 
'S': 68269758255538529041352015252552714935527092636738233256454142889393515803038, 
'IKPUB.X': 64060639660402362265226186893196199107809961268479605535018970443291735599009, 
'IKPUB.Y': 15813262433677063321684225909878319530480824782061511915847689366068953248338}

'''
#verification code: 936472
#reset code: 969056

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



registration = input("do you want to register your identity key? 'yes' or 'no' ")
if(registration == "yes"):
    IKRegReq(h, s, ikpubx, ikpuby)

else:
    print("not registered!")


verify = input("continue verification? 'yes' or 'no' ")
if(verify == "yes"):
    verify_code = int(input("enter verification code: "))
    IKRegVerify(verify_code)



#SPK GENERATION
print("generating SPK")
random.seed(102)
spk_secretkey = random.randint(0, E.order-2)
spk_Qa = spk_secretkey*P # my SPK public key
spk_pubx = spk_Qa.x
spk_puby = spk_Qa.y
random.seed(104)
spk_k = random.randint(0, E.order-3)
spk_R = spk_k*P
spk_lower_r = (spk_R.x) % n
spk_msg = (spk_pubx.to_bytes((spk_pubx.bit_length()+7)//8, byteorder='big')) + (spk_puby.to_bytes((spk_puby.bit_length()+7)//8, byteorder='big'))

spk_hashdata = spk_lower_r.to_bytes((spk_lower_r.bit_length()+7)//8, byteorder='big') + spk_msg
spk_h_object = SHA3_256.new()
spk_h_object.update(data=spk_hashdata)

spkh = (int.from_bytes(spk_h_object.digest(), byteorder='big'))% n
spks = (spk_k - (secretkey*int.from_bytes(spk_h_object.digest(), byteorder='big'))) % n
print("SPK secret: ", spk_secretkey)
print("SPK pub.x: ", spk_pubx)
print("SPK pub.y: ", spk_puby)
print("SPK hash: ", spkh)
print("SPK signature: ", spks)

server_response = []
spk_registration = input("do you want to register your SPK? 'yes' or 'no' ")
if(spk_registration == "yes"):
    server_response = SPKReg(spkh,spks,spk_pubx,spk_puby)

if(not server_response):
    print("something went wrong with the server response!")
    print(server_response)

else:
    print("checking validity of the response...")
    print(server_response)


response_spk_x = server_response[0]
response_spk_y = server_response[1]

print("server pub spk.x: ", response_spk_x)
print("server pub spk.y: ", response_spk_y)

server_spk_pub = Point(response_spk_x ,response_spk_y, curve)

#generating hmac key
T = spk_secretkey*server_spk_pub
T_x = T.x
T_y = T.y
U = T_x.to_bytes((T_x.bit_length()+7)//8, byteorder='big') + T_y.to_bytes((T_y.bit_length()+7)//8, byteorder='big') + b'NoNeedToRideAndHide'
k_hmac = SHA3_256.new()
k_hmac.update(data=U)

# generating 10 OTKs 
for i in range(0, 10):

    random.seed(200 + i)
    otk_secret = random.randint(0, E.order-2) 
    otk_pub = otk_secret*P
    otk_pub_x = otk_pub.x
    otk_pub_y = otk_pub.y

    hmac_data = otk_pub_x.to_bytes((otk_pub_x.bit_length()+7)//8, byteorder='big') + otk_pub_y.to_bytes((otk_pub_y.bit_length()+7)//8, byteorder='big')
    v_hmac = HMAC.new(key=k_hmac.digest(), digestmod=SHA256)
    v_hmac.update(msg=hmac_data)
    OTKReg(i,otk_pub_x, otk_pub_y, v_hmac.hexdigest())

    




