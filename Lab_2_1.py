import itertools
import random

def generate_polygram():
    letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    polygrams=[''.join(p) for p in itertools.product(letters,repeat=4)]
    return polygrams
polygram_list=generate_polygram()
with open('lab_2_input.txt','w') as f:
    for p in polygram_list:
        f.write(p+"\n")
shuffled_polygrams=polygram_list.copy()
random.shuffle(shuffled_polygrams)

polygram_key=dict(zip(polygram_list,shuffled_polygrams))
revese_polygram_key={v:k for k,v in polygram_key.items()}

def polygram_encrypt(plaintext):
    text=plaintext.upper().replace(" ","")
    while len(text)%4!=0:
        text+='$'
    cipher=""
    for i in range(0,len(text),4):
        block=text[i:i+4]
        cipher+=polygram_key.get(block,block)
    return cipher
def polygram_decrypt(ciphertext):
    text=""
    for i in range(0,len(ciphertext),4):
        block=ciphertext[i:i+4]
        text+=revese_polygram_key.get(block,block)
    return text
if __name__=="__main__":
    plain_text=input("Enter the plaintext: ")
    cipher_text=polygram_encrypt(plain_text)
    with open('lab_2_output.txt' , 'w') as f:
        f.write(cipher_text)
    print("Encryption complete. Ciphertext saved to lab_2_output.txt")
    decrypted_text = polygram_decrypt(cipher_text)
    print("Decrypted back to:", decrypted_text)