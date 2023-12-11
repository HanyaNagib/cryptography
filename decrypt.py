#importing necessary modules
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

#function for asymmetric decryption (RSA)
def decrypt_rsa(encrypted_aes_key, recipient_private_key):
    #importing the recipient's private key    
    key = RSA.import_key(recipient_private_key)
    #creating a new RSA cipher object using the key
    cipher_rsa = PKCS1_OAEP.new(key)
    #decrypting the symmetric key
    symmetric_key = cipher_rsa.decrypt(encrypted_aes_key)
    return symmetric_key

#function for decrypting the aes-encrypted message
def decrypt_aes(encrypted_message, symmetric_key, nonce, tag):
    #creating a new AES cipher object in EAX mode with the symmetric key and nonce
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    #decrypting and verifing the encrypted message using the tag
    decrypted_message = cipher_aes.decrypt_and_verify(encrypted_message, tag)
    return decrypted_message

#verifing the digital signature of the symmetric key
def verify_signature(symmetric_key, signature, sender_public_key):
    #importing the sender's public key
    key = RSA.import_key(sender_public_key)
    #creating a SHA-256 hash object for the symmetric key
    h = SHA256.new(symmetric_key)
    try:
        #verifing the signature using PKCS#1 v1.5 padding
        pkcs1_15.new(key).verify(h, signature)
        print("Signature is valid.")
        return True
    except (ValueError, TypeError):
        print("Signature verification failed.")
        return False

#opeing and reading the keys used for decryption
with open('recipient_private_key.pem', 'rb') as f:
    recipient_private_key = f.read()
with open('sender_public_key.pem', 'rb') as f:
    sender_public_key = f.read()
with open('encrypted_aes_key', 'rb') as f:
    encrypted_aes_key = f.read()
#read the files to be decrypted
with open('nonce', 'rb') as f:
    nonce = f.read()
with open('ciphertext', 'rb') as f:
    ciphertext = f.read()
with open('tag', 'rb') as f:
    tag = f.read()
#opeing and reading the signature for verification
with open('signature', 'rb') as f:
    signature = f.read()

#decrypting the encrypted symmetric key using the recipient's private key
symmetric_key = decrypt_rsa(encrypted_aes_key, recipient_private_key)

#verifing the digital signature using the sender's public key
if verify_signature(symmetric_key, signature, sender_public_key):
    #if it is valid then decrypt the message
    decrypted_message = decrypt_aes(ciphertext, symmetric_key, nonce, tag)
    print("Decrypted Message:", decrypted_message.decode('utf-8'))
else:
    print("Message could not be decrypted due to an invalid signature.")
