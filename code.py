from PIL import Image
import codecs
import pathlib
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode()
    return string_value

def hexifiyMessage(message):
  message += "    "
  numberMessage = []
  for letter in message:
    numberMessage.append(ord(letter))
  hexMessage = []
  for number in numberMessage:
    low, high = divmod(number, 0x10)
    hexMessage.append(hex(low))
    hexMessage.append(hex(high))
  return hexMessage

def calculateNewHex(messageValue: hex, pixelValue: int):
  low, high = divmod(pixelValue, 0x10)
  number = hex( (low<<4) | int(messageValue, 16) )
  return int(number, 16)

def findHiddenHex(pixelValue: int):
  low, high = divmod(pixelValue, 0x10)
  return high

def encryptPicture(hexMessage):
  messageCounter = 0
  for i in range(width):
      for j in range(height):
          
          # getting the RGB pixel value.
          r, g, b = pix[i, j]
            
          if(messageCounter+4 >= len(hexMessage)):
            break
          r = calculateNewHex(hexMessage[messageCounter], r)
          messageCounter+=1
          g = calculateNewHex(hexMessage[messageCounter], g)
          messageCounter+=1
          b = calculateNewHex(hexMessage[messageCounter], b)
          messageCounter+=1
          # setting the pixel value.
          pix[i, j] = r, g, b

          if(messageCounter+4 >= len(hexMessage)):
            break

def decryptPicture():
  message = []
  for i in range(width):
      for j in range(height):
          
          # getting the RGB pixel value.
          r, g, b = pix[i, j]

          r = findHiddenHex(r)
          g = findHiddenHex(g)
          b = findHiddenHex(b)
          # setting the pixel value.
          message.append(r)
          message.append(g)
          message.append(b)

  return message

def getKey(password_provided):
  password = password_provided.encode()
  salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"

  kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                  length=32,
                  salt=salt,
                  iterations=100000,
                  backend=default_backend())

  key = base64.urlsafe_b64encode(kdf.derive(password))
  print(key)



#####loading image
im = Image.open("/content/example.jpg")
pix = im.load()
width, height = im.size


#####message insertion in image (and encryption)
print("Unesi poruku:    ")
message = input()
print("Unesi yes za enkriptirani unos, inace bilo sta drugo")
choice = input()
if(choice == "yes"):
  print("Password:  ")
  password_provided = input()
  key = getKey(password_provided)
  fernet = Fernet(key)
  print(message)
  message = fernet.encrypt(message.encode())
  print(message)
hexMessage = hexifiyMessage(message)
encryptPicture(hexMessage)


##### decryption from image
numberedMessage = decryptPicture()
unicodeMessage = []
for i in range(len(numberedMessage)-4):
  number = hex( (numberedMessage[i]<<4) | numberedMessage[i+1] )
  i+=1
  unicodeMessage.append(number)

message = ""
counter = 0
for unicodes in unicodeMessage[0::2]:
  unicodes = unicodes[2:]
  if(unicodes == "20"):
    counter+=1
  if(unicodes != "20"):
    counter=0
  message += bytearray.fromhex(unicodes).decode('utf-8')
  if(counter > 1):
    break
message = message[:-2]

print("Unesi yes za unos lozinke, inace bilo sta drugo")
choice = input()
if(choice == "yes"):
  print("Unesi lozinku:    ")
  password = input()
  key = getKey(password_provided)
  fernet = Fernet(key)
  encrypted = fernet.decrypt(message)
print(message)
