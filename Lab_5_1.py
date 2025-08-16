import re
def normalize(text):
    return re.sub('[^A-Z]','',text.upper())

def otp_encrypt(text,key):
    text=normalize(text)
    key=normalize(key)
    if len(key)<len(text):
        raise ValueError("Key length must be as long as a plaintext.")
    ciphertext=[]
    for p,k in zip(text,key):
        c=(ord(p)-65+ord(k)-65)%26
        ciphertext.append(chr(c+65))
    return ''.join(ciphertext)

def otp_decrypt(ciphertext,key):
    ciphertext=normalize(ciphertext)
    key=normalize(key)
    if len(key)<len(ciphertext):
        raise ValueError("Key length must be as long as a plaintext.")
    text=[]
    for c,k in zip(ciphertext,key):
        p=(ord(c)-65-(ord(k)-65))%26
        text.append(chr(p+65))
    return ''.join(text)

if __name__=="__main__":
    with open('lab_5_input.txt','r') as f:
        plaintext=f.read().strip()
    with open('lab_5_key.txt','r') as f:
        key=f.read().strip()

    ciphertext=otp_encrypt(plaintext,key)
    with open('lab_5_ciphertext.txt','w') as f:
        f.write(ciphertext)
    print("Ciphertext save in lab_5_ciphertext.txt")

    decrypt=otp_decrypt(ciphertext,key)
    with open('lab_5_output.txt','w') as f:
        f.write(decrypt)
    print("Output save in lab_5_ciphertext.txt")
