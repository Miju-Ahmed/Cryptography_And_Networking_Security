import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
class PGPSystem:
    def __init__(self):
        # Generate RSA key pairs using built-in functions
        self.sender_key = RSA.generate(1024)
        self.receiver_key = RSA.generate(1024)
        
        print("PGP System Initialized with Built-in RSA")
        print(f"Sender Key Size: {self.sender_key.size_in_bits()} bits")
        print(f"Receiver Key Size: {self.receiver_key.size_in_bits()} bits")
    
    def pgp_authentication(self, message):
        print("\n=== PGP AUTHENTICATION SERVICE ===")
        print(f"1. Sender creates message: '{message}'")
        
        # Step 2: Generate SHA-1 hash (160-bit)
        message_bytes = message.encode('utf-8')
        hash_obj = SHA1.new(message_bytes)
        print(f"2. SHA-1 generates 160-bit hash: {hash_obj.hexdigest()[:32]}...")
        
        # Step 3: Encrypt hash with sender's private key (Digital Signature)
        signature = pkcs1_15.new(self.sender_key).sign(hash_obj)
        print(f"3. Hash encrypted with sender's private key (signature created)")
        
        # Prepend signature to message
        signed_message = {
            'message': message,
            'signature': signature,
            'hash': hash_obj.digest()
        }
        print(f"4. Signature prepended to message")
        
        return signed_message
    
    def pgp_authentication_verify(self, signed_message):
        print("\n=== PGP AUTHENTICATION VERIFICATION ===")
        
        message = signed_message['message']
        signature = signed_message['signature']
        
        print(f"1. Receiver got message: '{message}'")
        
        # Step 4: Decrypt signature using sender's public key
        try:
            # Generate new hash of received message
            new_hash = SHA1.new(message.encode('utf-8'))
            print(f"2. Generated new hash: {new_hash.hexdigest()[:32]}...")
            
            # Verify signature using sender's public key
            pkcs1_15.new(self.sender_key.publickey()).verify(new_hash, signature)
            print(f"3. Signature decrypted with sender's public key")
            print(f"4. Hash comparison: MATCH - Message is AUTHENTIC")
            return True
            
        except (ValueError, TypeError):
            print(f"4. Hash comparison: MISMATCH - Message is NOT AUTHENTIC")
            return False
        
    def pgp_confidentiality(self, message):
        print("\n=== PGP CONFIDENTIALITY SERVICE ===")
        print(f"1. Sender generates message: '{message}'")
        
        # Step 2: Generate random 128-bit session key
        session_key = get_random_bytes(16)  # 128 bits = 16 bytes
        print(f"2. Random 128-bit session key generated")
        
        # Step 3: Encrypt message using AES with session key
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        iv = cipher_aes.iv
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        encrypted_message = cipher_aes.encrypt(padded_message)
        print(f"3. Message encrypted using AES with session key")
        
        # Step 4: Encrypt session key with RSA using recipient's public key
        cipher_rsa = PKCS1_OAEP.new(self.receiver_key.publickey())
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        print(f"4. Session key encrypted with RSA using recipient's public key")
        print(f"5. Encrypted session key prepended to message")
        
        # Create encrypted package
        encrypted_package = {
            'encrypted_session_key': encrypted_session_key,
            'iv': iv,
            'encrypted_message': encrypted_message
        }
        
        return encrypted_package
    
     
    def pgp_confidentiality_decrypt(self, encrypted_package):
        print("\n=== PGP CONFIDENTIALITY DECRYPTION ===")
        
        # Step 5: Decrypt session key using receiver's private key
        cipher_rsa = PKCS1_OAEP.new(self.receiver_key)
        session_key = cipher_rsa.decrypt(encrypted_package['encrypted_session_key'])
        print(f"1. Session key decrypted using receiver's private key")
        
        # Step 6: Decrypt message using session key
        cipher_aes = AES.new(session_key, AES.MODE_CBC, encrypted_package['iv'])
        decrypted_padded = cipher_aes.decrypt(encrypted_package['encrypted_message'])
        decrypted_message = unpad(decrypted_padded, AES.block_size).decode('utf-8')
        print(f"2. Message decrypted using session key")
        print(f"3. Decrypted message: '{decrypted_message}'")
        
        return decrypted_message
    
    def pgp_complete_service(self, message):
        print("\n" + "="*60)
        print("COMPLETE PGP SERVICE - AUTHENTICATION + CONFIDENTIALITY")
        print("="*60)
        
        # First apply authentication (digital signature)
        signed_message = self.pgp_authentication(message)
        
        # Then apply confidentiality to the signed message
        message_with_signature = f"{signed_message['message']}|SIG|{len(signed_message['signature'])}"
        encrypted_package = self.pgp_confidentiality(message_with_signature)
        
        # Combine both
        complete_package = {
            'encrypted_package': encrypted_package,
            'signature': signed_message['signature']
        }
        
        return complete_package, signed_message
    

    def pgp_complete_decrypt(self, complete_package, original_signed):
        print("\n" + "="*60)
        print("COMPLETE PGP DECRYPTION + VERIFICATION")
        print("="*60)
        
        # First decrypt the message
        decrypted_message = self.pgp_confidentiality_decrypt(complete_package['encrypted_package'])
        
        # Extract original message
        parts = decrypted_message.split('|SIG|')
        original_message = parts[0]
        
        # Verify authentication using the signature
        signed_msg = {'message': original_message, 'signature': complete_package['signature']}
        is_authentic = self.pgp_authentication_verify(signed_msg)
        
        return original_message, is_authentic

# Initialize PGP System
pgp = PGPSystem()


# Test message
message = "This is a confidential message for PGP testing"

print("="*70)
print("TESTING PGP SERVICES WITH BUILT-IN RSA AND AES")
print("="*70)

# Test 1: Authentication Service Only
print("\n>>> TESTING AUTHENTICATION SERVICE <<<")
signed_msg = pgp.pgp_authentication(message)
auth_result = pgp.pgp_authentication_verify(signed_msg)

# Test 2: Confidentiality Service Only  
print("\n>>> TESTING CONFIDENTIALITY SERVICE <<<")
encrypted_pkg = pgp.pgp_confidentiality(message)
decrypted_msg = pgp.pgp_confidentiality_decrypt(encrypted_pkg)

# Test 3: Complete PGP Service (Authentication + Confidentiality)
print("\n>>> TESTING COMPLETE PGP SERVICE <<<")
complete_pkg, signed_original = pgp.pgp_complete_service(message)
final_msg, final_auth = pgp.pgp_complete_decrypt(complete_pkg, signed_original)

print("\n" + "="*70)
print("FINAL RESULTS")
print("="*70)
print(f"Original Message: '{message}'")
print(f"Authentication Test: {'PASSED' if auth_result else 'FAILED'}")
print(f"Confidentiality Test: {'PASSED' if decrypted_msg == message else 'FAILED'}")
print(f"Complete Service: {'PASSED' if final_msg == message and final_auth else 'FAILED'}")
print(f"Final Decrypted: '{final_msg}'")
print(f"Final Authentication: {'VERIFIED' if final_auth else 'FAILED'}")