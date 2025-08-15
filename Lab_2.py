polygram_key = {
    "THE": "XQZ",
    "AND": "MNO",
    "ING": "PLK",
    "YOU": "RTS",
    "FOR": "ABC",
    "ARE": "DEF",
    "ENT": "GHI",
    "ION": "JKL"
}
reverse_polygram_key={v:k for k,v in polygram_key.items()}

def polygram_encrypt(plaintext):
    text=plaintext.upper().replace(" ","")
    while len(text)%3!=0:
        text+="X"
    cipher=""
    for i in range(0,len(text),3):
        block=text[i:i+3]
        cipher += polygram_key.get(block,block)
    return cipher
def polygram_decrypt(ciphertext):
    text=""
    for i in range(0,len(ciphertext),3):
        block=ciphertext[i:i+3]
        text+=reverse_polygram_key.get(block,block)
    return text
if __name__=="__main__":
    plain_text=input("Enter the plaintext: ")
    cipher_text=polygram_encrypt(plain_text)
    decrypt_text=polygram_decrypt(cipher_text)
    print(f"Plaintext   : {plain_text}")
    print(f"Ciphertext  : {cipher_text}")
    print(f"Decrypttext : {decrypt_text}")