from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from Crypto.Cipher import  AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class PGP:
    def __init__(self):
        self.sender_key = RSA.generate(1024)
        self.receiver_key = RSA.generate(1024)
    def authentication(self, message):
        h = SHA1.new(message.encode())
        signature = pkcs1_15.new(self.sender_key).sign(h)
        return {'message':message, 'signature':signature}
    def verify(self, signed_message):
        h = SHA1.new(signed_message['message'].encode())
        try:
            pkcs1_15.new(self.sender_key.public_key()).verify(h, signed_message['signature'])
            return True
        except (ValueError, TypeError):
            return False
    def encrypt(self, message):
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ct = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
        cipher_rsa = PKCS1_OAEP.new(self.receiver_key.public_key())
        enc_key = cipher_rsa.encrypt(session_key)
        return {'enc_key':enc_key, 'iv':cipher_aes.iv, 'ct':ct}
    def decrypt(self, package):
        cipher_rsa = PKCS1_OAEP.new(self.receiver_key)
        session_key = cipher_rsa.decrypt(package['enc_key'])
        cipher_aes = AES.new(session_key, AES.MODE_CBC, package['iv'])
        pt = unpad(cipher_aes.decrypt(package['ct']), AES.block_size)
        return pt.decode()
    def pgp_send(self, message):
        signed = self.authentication(message)
        full_message = f"{message}|SIg"
        encrypted = self.encrypt(full_message)
        return encrypted, signed['signature']
    def pgp_receive(self, encrypted, signature):
        decrypted = self.decrypt(encrypted)
        message = decrypted.split('|SIG')[0]
        return message, self.verify({'message':message, 'signature':signature})
    
pgp = PGP()

msg = "This is a confidential message for PGP testing"

print("\n🔹 Testing Authentication")
signed = pgp.authentication(msg)
print("Verified:", pgp.verify(signed))

print("\n🔹 Testing Confidentiality")
enc = pgp.encrypt(msg)
dec = pgp.decrypt(enc)
print("Decrypted:", dec)

print("\n🔹 Testing Complete PGP")
enc_pkg, sig = pgp.pgp_send(msg)
final_msg, auth_ok = pgp.pgp_receive(enc_pkg, sig)
print("Decrypted:", final_msg)
print("Authentication Verified:", auth_ok)