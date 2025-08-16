import re
def normalize(text):
    return re.sub('[^A-Z]','',text.upper())
def otp_encrypt(text,key):
    text=normalize(text)
    key=normalize(key)
    if len(key)<len(text):
        raise ValueError("Key length must be as long as a plaintext.")
    ciphertext=[]
    for t,k in zip(text,key):
        c=(ord(t)-65+ord(k)-65)%26
        ciphertext.append(chr(c+65))
    return ''.join(ciphertext)
def otp_decrypt(ciphertext,key):
    ciphertext=normalize(ciphertext)
    key=normalize(key)
    if len(key)<len(ciphertext):
        raise ValueError("Key length must be as long as a plaintext.")
    plaintext=[]
    for c,k in zip(ciphertext,key):
        p=(ord(c)-65-(ord(k)-26))%26
        plaintext.append(chr(p+65))
    return ''.join(plaintext)

if __name__=="__main__":
    plaintext = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLY UNIVERSITY OF RAJSHAHI BANGLADESH"
    with open("lab_5_key.txt", "r") as f:
        key = f.read().strip()
    ciphertext = otp_encrypt(plaintext, key)
    with open("lab_5_ciphertext.txt", "w") as f:
        f.write(ciphertext)
    print("Ciphertext saved in lab_5_ciphertext.txt")
    decrypted = otp_decrypt(ciphertext, key)
    with open("lab_5_decrypted.txt", "w") as f:
        f.write(decrypted)
    print("Decrypted plaintext saved in lab_5_decrypted.txt")
