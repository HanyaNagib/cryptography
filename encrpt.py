#importing necessary modules
import smtplib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

#function for asymmetric encryption (RSA)
def encrypt_rsa(symmetric_key, recipient_public_key):
    #importing the recipient's public key
    key = RSA.import_key(recipient_public_key)
    #creating a new RSA cipher object using the key
    cipher_rsa = PKCS1_OAEP.new(key)
    #encrypting the symmetric key 
    encrypted_aes_key = cipher_rsa.encrypt(symmetric_key)
    return encrypted_aes_key

#function for symmetric encryption (AES)
def encrypt_aes(message, symmetric_key):
    #creating a new AES cipher object using the symmetric key and EAX mode
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    #generating a nonce for the cipher
    nonce = cipher_aes.nonce
    #encrypting and digesting message using AES
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    return nonce, ciphertext, tag

#function for creating the digital signature
def sign_message(symmetric_key, sender_private_key):
    key = RSA.import_key(sender_private_key)
    #creating a SHA-256 hash object for the symmetric key
    h = SHA256.new(symmetric_key)
    #signing the message using PKCS#1 v1.5 padding
    signature = pkcs1_15.new(key).sign(h)
    return signature

#function for sending the email
def send_secure_email(sender, receiver, subject, message, app_password):
    #the SMTP server settings for Gmail
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    username = 'hanyanagibb23@gmail.com'

    #reading the keys used for encrypting and signing the message from files
    with open('sender_private_key.pem', 'rb') as f:
        sender_private_key = f.read()
    with open('recipient_public_key.pem', 'rb') as f:
        recipient_public_key = f.read()
    with open('symmetric_key.bin', 'rb') as f:
        symmetric_key = f.read() 

    #signing the symmetric key with the sender's private key
    signature = sign_message(symmetric_key, sender_private_key)

    #encrypting the AES key with the recipient's public key
    encrypted_aes_key = encrypt_rsa(symmetric_key, recipient_public_key)

    #encrypt the email content with AES
    nonce, ciphertext, tag = encrypt_aes(message, symmetric_key)

    #creating MIME message that represents a multipart message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = subject

    #MIME application is used to attach the encrypted content as binary files
    #subtype is octet-stream to indicate the content is binary data
    #conent-disposition header is used to indicate that the content should be treated as separate attachments
    #attaching the encrypted aes key
    attachment = MIMEApplication(encrypted_aes_key, _subtype='octet-stream', name='encrypted_aes_key')
    attachment.add_header('Content-Disposition', 'attachment', filename='encrypted_aes_key')
    msg.attach(attachment)
    #attaching the nonce
    attachment = MIMEApplication(nonce, _subtype='octet-stream', name='nonce')
    attachment.add_header('Content-Disposition', 'attachment', filename='nonce')
    msg.attach(attachment)
    #attaching the ciphertext
    attachment = MIMEApplication(ciphertext, _subtype='octet-stream', name='ciphertext')
    attachment.add_header('Content-Disposition', 'attachment', filename='ciphertext')
    msg.attach(attachment)
    #attaching the tag
    attachment = MIMEApplication(tag, _subtype='octet-stream', name='tag')
    attachment.add_header('Content-Disposition', 'attachment', filename='tag')
    msg.attach(attachment)
    #attaching the digital signature
    attachment = MIMEApplication(bytes(signature), _subtype='octet-stream', name='signature')
    attachment.add_header('Content-Disposition', 'attachment', filename='signature')
    msg.attach(attachment)


    #establishing a connection with the SMTP server
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(username, app_password)

    #sending the email
    server.sendmail(sender, receiver, msg.as_string())
    print("Email sent successfully!")

    #closing the connection to the SMTP server
    server.quit()

#credentials and email contents
sender_email = 'hanyanagibb23@gmail.com' #input("please enter your email: \n") #hanyanagibb23@gmail.com
receiver_email = 'hanyanagibe@gmail.com' #input("Please enter the receiver's email: \n") #hanyanagibe@gmail.com
email_subject = input("Please enter the email subject: \n")
email_message = input("Please enter the email message: \n")
app_password = 'bvzllyrzqyjqjbmh' #input("Please enter your app password: \n") #bvzllyrzqyjqjbmh  

send_secure_email(sender_email, receiver_email, email_subject, email_message, app_password)