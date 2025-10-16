from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class PGPClass:
    def __init__(self):
        self.sender_key = RSA.generate(1024)
        self.receiver_key = RSA.generate(1024)
        print("PGP initialized")
    def authenticate(self, message):
        h = SHA1.new(message.encode())
        signature = pkcs1_15.new(self.sender_key).sign(h)
        return {'message':message, 'signature':signature}
    def verify(self, signed_msg):
        h = SHA1.new(signed_msg['message'].encode())
        try:
            pkcs1_15.new(self.sender_key.public_key()).verify(h,signed_msg['signature'])
            return True
        except (ValueError, TypeError):
            return False
    def encrypt_message(self, message):
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ct = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
        cipher_rsa = PKCS1_OAEP.new(self.receiver_key.public_key())
        enc_key = cipher_rsa.encrypt(session_key)
        return {'enc_key':enc_key, 'iv':cipher_aes.iv, 'ct':ct}
    def decrypt_message(self, package):
        cipher_rsa = PKCS1_OAEP.new(self.receiver_key)
        session_key = cipher_rsa.decrypt(package['enc_key'])
        cipher_aes = AES.new(session_key, AES.MODE_CBC, package['iv'])
        pt = unpad(cipher_aes.decrypt(package['ct']), AES.block_size)
        return pt.decode()
    
    def pgp_send(self, message):
        signed = self.authenticate(message)
        full_message = f"{message}|SIGNED"
        encrypted = self.encrypt_message(full_message)
        return encrypted, signed['signature']
    def pgp_received(self, encrypted, signature):
        decrypted = self.decrypt_message(encrypted)
        message = decrypted.split('|SIGNED')[0]
        return message, self.verify({'message':message, 'signature':signature})
    

pgp = PGPClass()
msg = "Hello world"
print("Testing Authentication")
signed = pgp.authenticate(msg)
print("Verified: ", pgp.verify(signed))

print("\nTesting Confidentiality ")
enc = pgp.encrypt_message(msg)
dec = pgp.decrypt_message(enc)
print(f"Encrypted : {enc}\n Decrypted : {dec}")

print("\n complete pgp")
enc_pkg, sig = pgp.pgp_send(msg)
final_msg, auth_ok = pgp.pgp_received(enc_pkg, sig)
print("Decrypted : ", final_msg)
print("Authentication verified : ", auth_ok)