import itertools
import random

def generate_polygram_list(r = 3):
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    polygrams = [''.join(p) for p in itertools.product(letters, repeat=r)]
    return polygrams
polygram_list = generate_polygram_list()
with open("polygram_list.txt", 'w') as f:
    for p in polygram_list:
        f.write(p+'\n')
shuffled_polygram = polygram_list.copy()
random.shuffle(shuffled_polygram)

polygram_key = dict(zip(polygram_list, shuffled_polygram))
reverse_polygram_key = {v:k for k,v in polygram_key.items()}

def polygram_encrypt(pt):
    text = pt.upper().replace(" ", "")
    while len(text)%3!=0:
        text+='$'
    ct = ""
    for i in range(0, len(text), 3):
        block = text[i:i+3]
        ct += polygram_key.get(block,block)
    return ct
def decrypt(ct):
    text =""
    for i in range(0,len(ct),3):
        block = ct[i:i+3]
        text+= reverse_polygram_key.get(block,block)
    return text

if __name__=="__main__":
    # plain_text=input("Enter the plaintext: ")
    plain_text = "MynameisMdMijuAhmed"
    cipher_text=polygram_encrypt(plain_text)
    print(f"Cipher text : {cipher_text}")
    with open('lab_2_output.txt' , 'w') as f:
        f.write(cipher_text)
    print("Encryption complete. Ciphertext saved to lab_2_output.txt")
    decrypted_text = decrypt(cipher_text)
    print("Decrypted back to:", decrypted_text)
