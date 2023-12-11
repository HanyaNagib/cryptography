#importing RSA module from Crypto library
from Crypto.PublicKey import RSA
import os

#function that generates a RSA key pair
def generate_rsa_key_pair():
    #generating the key with length of 2048 bits
    key = RSA.generate(2048)
    #exporting the private and public keys as strings
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

#generating key pairs for sender and recipient 
#sender's private key is for the digital signatures
#sender's public key is for verifying the authenticity of the digital signature
sender_private_key, sender_public_key = generate_rsa_key_pair()
#recipient's private key is for decrypting the message
#recipient's public key is for encrypting the message
recipient_private_key, recipient_public_key = generate_rsa_key_pair()

#saving the keys to files
with open('sender_private_key.pem', 'wb') as f:
    f.write(sender_private_key)

with open('sender_public_key.pem', 'wb') as f:
    f.write(sender_public_key)

with open('recipient_private_key.pem', 'wb') as f:
    f.write(recipient_private_key)

with open('recipient_public_key.pem', 'wb') as f:
    f.write(recipient_public_key)

#function to generate key for aes encryption
def generate_symmetric_key():
    #32 bytes for AES-256
    symmetric_key = os.urandom(32)  
    #saving it in a file
    with open('symmetric_key.bin', 'wb') as f:
        f.write(symmetric_key)

generate_symmetric_key()