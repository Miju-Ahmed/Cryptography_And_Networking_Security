#Caesar_Cipher.py
# def encrypt(pt, shift=3):
#     ct = ""
#     for char in pt:
#         if char.isalpha():
#             offset = 65 if char.isupper() else 97
#             en = chr((ord(char)-offset+shift)%26 + offset)
#             ct += en
#         else:
#             ct += char
#     return ct
# def decrypt(ct, shift=3):
#     return encrypt(ct, -shift)
# plaintext = "Miju Ahmed"
# ct = encrypt(plaintext)
# dec = decrypt(ct)
# print(f"Plain text: {plaintext}\n Ciphertext : {ct}\n Decrypt : {dec}")

#Transposition Cipher
# def encrypt(pt, width=5):
#     length = len(pt)
#     ct = ""
#     for i, char in enumerate(pt):
#         print(char, end=" ")
#         if (i+1)%width==0:
#             print()
#     print()
#     for k in range(width):
#         for i in range(k,length,width):
#             ct += pt[i]
#     return ct
# def decryption(ct, width=5):
#     length = len(ct)
#     pt = [' ']*length
#     idx = 0
#     for k in range(width):
#         for i in range(k, length, width):
#             pt[i] = ct[idx]
#             idx+=1
#     return ''.join(pt)

# plaintext = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLGY UNIVERSITY OF RAJSHAHI BANGLADESH"
# ciphertext = encrypt(plaintext)
# decrypted_text = decryption(ciphertext)
# print(f"Plaintext:           {plaintext}")
# print(f"Ciphertext:          {ciphertext}")
# print(f"Decrypted Plaintext: {decrypted_text}")


# #double Transposition
# def encrypt(pt, width=10):
#     length=len(pt)
#     ct=""
#     for i, char in enumerate(pt):
#         print(char,end=" ")
#         if (i+1)%width==0:
#             print()
#     print()
#     for k in range(width):
#         for i in range(k,length,width):
#             ct+=pt[i]
#     return ct
# def decrypt(ct,width=10):
#     length=len(ct)
#     pt=[' ']*length
#     idx=0
#     for k in range(width):
#         for i in range(k,length,width):
#             pt[i]=ct[idx]
#             idx+=1
#     return ''.join(pt)

# plaintext = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLGY UNIVERSITY OF RAJSHAHI BANGLADESH"
# print("First Transposition:\n")
# ciphertext1 = encrypt(plaintext)
# print("Second Transposition:\n")
# ciphertext2=encrypt(ciphertext1)

# decrypted_text2 = decrypt(ciphertext2)
# decrypted_text1=decrypt(decrypted_text2)
# print(f"Plaintext:           {plaintext}")
# print(f"Ciphertext1:          {ciphertext1}")
# print(f"Ciphertext2:          {ciphertext2}")
# print(f"Decrypted Plaintext2: {decrypted_text2}")
# print(f"Decrypted Plaintext1: {decrypted_text1}")



# #One-Time-Pad
# def encrypt(pt):
#     key=""
#     with open("Sender_Pad.txt","r") as file:
#         key=file.read().strip()
#     cp=""
#     idx=0
#     for ch in pt:
#         x=(ord(ch)+ord(key[idx]))%26
#         idx+=1
#         cp+=chr(ord('A')+x+1)
#     remaining_key=key[idx:]
#     key_used=key[:idx]
#     with open("Sender_Pad.txt","w") as file:
#         file.write(remaining_key)
#     return cp,key_used,remaining_key
# def decrypt(ct):
#     key=""
#     with open("Receiver_Pad.txt","r") as file:
#         key=file.read().strip()
#     pt=""
#     idx=0
#     for ch in ct:
#         x=(ord(ch)-ord(key[idx]))%26
#         idx+=1
#         pt+=(chr(ord('A')+x-1))
#     remaining_key=key[idx:]
#     key_used=key[:idx]
#     with open("Receiver_Pad.txt",'w') as file:
#         file.write(remaining_key)
#     return pt,key_used,remaining_key

# plaintext = "ONETIMEPAD"
# ciphertext, key_used, remaining_key = encrypt(plaintext)
# decrypted_text, key_used, remaining_key = decrypt(ciphertext)
# print(f"Plaintext:           {plaintext}")
# print(f"Ciphertext:          {ciphertext}, Key used: {key_used}, Remaining key: {remaining_key}")
# print(f"Decrypted Plaintext: {decrypted_text}, Key used: {key_used}, Remaining key: {remaining_key}")



# #Lehmann
# import random
# def lehmann_prime(p,t=10):
#     if p<2:
#         return False
#     if p==2:
#         return True
#     for _ in range(t):
#         a=random.randint(2,p-1)
#         e=(p-1)//2
#         res=pow(a,e,p)
#         if res!=1 and res!=p-1:
#             return False
#     return True
# numbers=[random.randint(3,1000) for _ in range(10)]
# for num in numbers:
#     if lehmann_prime(num):
#         print(f"{num} is prime")
#     else:
#         print(f"{num} is composite")


# # Robin-Miller
# import random
# def rabin_miller_prime(p,k=5):
#     if p<2:
#         return False
#     if p<=3:
#         return True
#     if p%2==0:
#         return False
#     m=p-1
#     b=0
#     while m%2==0:
#         m//=2
#         b+=1
#     for _ in range(k):
#         a=random.randint(2,p-1)
#         z=pow(a,m,p)
#         if z==1 or z==p-1:
#             continue
#         for _ in range(b-1):
#             z=pow(z,2,p)
#             if z==p-1:
#                 break
#             else:
#                 return False
#     return True
# numbers=[random.randint(3,1000) for _ in range(10)]
# for num in numbers:
#     result=rabin_miller_prime(num,k=5)
#     status = "Probably Prime" if result else "Composite"
#     print(f"{num:4}: {status}")


# MD5
# import hashlib
# def generate_md5_hash(pt):
#     md_hash=hashlib.md5()
#     md_hash.update(pt.encode('utf-8'))
#     return md_hash.hexdigest()
# pt = "Miju Chowdhury"
# hash_value = generate_md5_hash(pt)
# print(f"Plain text : {pt}")
# print(f"Hash Value : {hash_value}")

# # SHA
# import hashlib

# def hash_message(message, algorithm='sha256'):

#     message_bytes = message.encode('utf-8')

#     if algorithm == 'sha1':
#         hash_obj = hashlib.sha1(message_bytes)
#     elif algorithm == 'sha224':
#         hash_obj = hashlib.sha224(message_bytes)
#     elif algorithm == 'sha256':
#         hash_obj = hashlib.sha256(message_bytes)
#     elif algorithm == 'sha384':
#         hash_obj = hashlib.sha384(message_bytes)
#     elif algorithm == 'sha512':
#         hash_obj = hashlib.sha512(message_bytes)
#     else:
#         print("Invalid algorithm")

#     return hash_obj.hexdigest()

# message = "Miju Chowdhury"
# algorithm = "sha1"

# hashed_output = hash_message(message, algorithm)
# print(f"Plaintext: {message}")
# print(f"Algorithm: {algorithm}")
# print(f"Hashed Output using {algorithm.upper()}: {hashed_output}")



# RSA

e=79
d = 1019
M=6880023
n=3337

M_str = str(M)
msg_block=[]
for i in range(0, len(M_str), 3):
    block = M_str[i:i+3]
    msg_block.append(int(block))

cipher_block=[]
for m in msg_block:
    c = pow(m,e,n)
    cipher_block.append(c)

cipher_text = ""
for c in cipher_block:
    c_str = str(c).zfill(4)
    cipher_text += c_str

cipher_block = []
for i in range(0, len(cipher_text), 4):
    block = cipher_text[i:i+4]
    cipher_block.append(int(block))

decrypted_text=""
for i,c in enumerate(cipher_block):
    m=pow(c,d,n)
    if i<len(cipher_block)-1:
        m_str=str(m).zfill(3)
    else:
        remaining_length=len(M_str)-len(decrypted_text)
        m_str=str(m).zfill(remaining_length)
    decrypted_text+=m_str
decrypted_text=decrypted_text[-len(M_str):]
print(f"Plain Text:     {M_str}")
print(f"Cipher Text:    {cipher_text}")
print("Decrypted Text:", decrypted_text)

